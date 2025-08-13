// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/microsoft/go/_util/internal/checksum"
)

const description = `
This command signs build artifacts using MicroBuild. It is used in the Microsoft build of Go build pipeline.
Use '-n' to test the command locally.

Signs in multiple passes. Some steps only apply to certain types of archives:

1. Archive entries. Extracts specific entries from inside each archive, signs, and repacks.
2. Notarize. macOS archives get a notarization ticket attached to the tar.gz.
3. Signatures. Creates sig files for each archive.
4. Locally creates a .sha256 file for each archive.

See /eng/_util/cmd/sign/README.md for more information.
`

var (
	filesGlob          = flag.String("files", "eng/signing/tosign/*", "Glob of Go archives to sign.")
	destinationDir     = flag.String("o", "eng/signing/signed", "Directory to store signed files.")
	consolidateDiagDir = flag.String("consolidate-diag-dir", "eng/signing/diag", "Directory to store consolidated diagnostic files.")
	tempDir            = flag.String("temp-dir", "eng/signing/signing-temp", "Directory to store temporary files.")
	signingCsprojDir   = flag.String("signing-csproj-dir", "eng/signing", "Directory containing Sign.csproj and related files.")

	signType = flag.String("sign-type", "test",
		"Type of signing to perform. Options: test, real. "+
			// https://github.com/microsoft/go-lab/issues/231
			"Test signing skips using MicroBuild tooling because it throws exception 'The test signing method for cert (8020) has NOT been implemented.'")

	timeout = flag.Duration("timeout", 0,
		"Timeout for signing operations. Zero means no timeout. "+
			"Any MSBuild processes launched by this tool are be manually killed. "+
			"If set to a value lower than AzDO pipeline timeout, this helps avoid pipeline breakage when uploading MSBuild outputs.")
	dryRun = flag.Bool("n", false, "Dry run: don't run the MSBuild signing tooling at all, even in test mode. This works on non-Windows platforms.")
)

func main() {
	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// A context for timeout. This timeout is mainly here to make sure child MSBuild processes are
	// terminated. There are some ctx.Err() checks sprinkled into the Go code, but canceling
	// quickly during the packaging/repackaging work in Go is not currently important: the Go work
	// takes an insignificant amount of time compared to the signing service calls in MSBuild.
	var ctx context.Context
	if *timeout == 0 {
		ctx = context.Background()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(*timeout))
		defer cancel()
	}

	archives, err := findArchives(ctx, *filesGlob)
	if err != nil {
		return err
	}

	log.Println("Signing individual files extracted from archives")

	individualFilesToSign, err := flatMapSlice(archives, func(a *archive) ([]*fileToSign, error) {
		return a.prepareEntriesToSign(ctx)
	})
	if err != nil {
		return err
	}

	if err := sign(ctx, "1-Individual", individualFilesToSign); err != nil {
		return err
	}

	log.Println("Notarizing macOS individual files")

	individualFilesToNotarize, err := flatMapSlice(archives, func(a *archive) ([]*fileToSign, error) {
		return a.prepareIndividualNotarize(ctx)
	})

	if err := sign(ctx, "2-Notarize-Individual", individualFilesToNotarize); err != nil {
		return err
	}

	for _, a := range archives {
		if err := a.repackSignedEntries(ctx); err != nil {
			return err
		}
	}

	log.Println("Notarizing macOS bundles")

	filesToNotarize, err := flatMapSlice(archives, func(a *archive) ([]*fileToSign, error) {
		return a.prepareBundleNotarize(ctx)
	})
	if err != nil {
		return err
	}

	if err := sign(ctx, "3-Notarize-Bundles", filesToNotarize); err != nil {
		return err
	}

	for _, a := range archives {
		if err := a.unpackBundleNotarize(ctx); err != nil {
			return err
		}
	}

	log.Println("Creating signature files")

	signatureFiles, err := flatMapSlice(archives, func(a *archive) ([]*fileToSign, error) {
		return a.prepareArchiveSignatures(ctx)
	})
	if err != nil {
		return err
	}

	if err := sign(ctx, "4-Sigs", signatureFiles); err != nil {
		return err
	}

	log.Println("Copying finished files to destination")
	log.Printf("Destination directory: %q", *destinationDir)

	for _, a := range archives {
		if err := a.copyToDestination(ctx); err != nil {
			return err
		}
	}

	log.Println("Generating checksum files")

	for _, a := range archives {
		if err := checksum.WriteSHA256ChecksumFile(filepath.Join(*destinationDir, a.name)); err != nil {
			return err
		}
	}

	log.Println("Consolidating diagnostic files")
	log.Printf("Consolidated diagnostic directory: %q", *consolidateDiagDir)

	if err := consolidateDiagnosticFiles(); err != nil {
		return err
	}

	return nil
}

func findArchives(ctx context.Context, glob string) ([]*archive, error) {
	files, err := filepath.Glob(glob)
	if err != nil {
		return nil, fmt.Errorf("failed to glob files: %v", err)
	}

	archives := make([]*archive, 0, len(files))

	// Check for duplicate filenames. At the end of signing, we will put all the results in the
	// same directory (even if the sources came from different directories), so catching this
	// early saves time.
	//
	// Use lowercase because we sign on a Windows machine with a case-insensitive filesystem.
	archiveFilenames := make(map[string]string)

	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Ignore checksum files: we always generate new ones.
		if strings.HasSuffix(f, ".sha256") {
			continue
		}

		filenameLower := strings.ToLower(filepath.Base(f))
		if existingF, ok := archiveFilenames[filenameLower]; ok {
			return nil, fmt.Errorf("duplicate archive %q, already found %q (comparing lowercase filename)", f, existingF)
		}
		archiveFilenames[filenameLower] = f

		a, err := newArchive(f)
		if err != nil {
			return nil, fmt.Errorf("failed to process %q: %v", f, err)
		}
		archives = append(archives, a)
	}

	if len(archives) == 0 {
		return nil, fmt.Errorf("no archives found to sign matching glob %q", *filesGlob)
	}

	return archives, nil
}

func sign(ctx context.Context, step string, files []*fileToSign) error {
	if len(files) == 0 {
		log.Printf("No files to sign for step %q", step)
		return nil
	}

	var sb strings.Builder
	sb.WriteString("<Project>\n")
	sb.WriteString("  <ItemGroup>\n")
	for _, f := range files {
		f.WriteMSBuildItem(&sb)
	}
	sb.WriteString("  </ItemGroup>\n")
	sb.WriteString("</Project>\n")

	log.Printf("Signing with props file content:\n%s\n", sb.String())
	if *dryRun {
		log.Printf("Dry run: skipping signing.")
		return nil
	}
	if *signType == "test" {
		log.Printf("Testing signing: skipping MicroBuild tooling.")
		for _, f := range files {
			if strings.HasSuffix(f.fullPath, ".sig") {
				log.Printf("Replacing file with placeholder content to reduce size and simulate signature: %q", f.fullPath)
				// Get a checksum to make the file content unique. Otherwise,
				// publishing rejects the repeated file content.
				data, err := os.ReadFile(f.fullPath)
				if err != nil {
					return fmt.Errorf("failed to read file %q: %v", f.fullPath, err)
				}
				checksum := fmt.Sprintf("%x", sha256.Sum256(data))
				if err := os.WriteFile(
					f.fullPath,
					fmt.Appendf(nil, "This is a placeholder test signature file. Original content checksum: %v\n", checksum),
					0o666,
				); err != nil {
					return fmt.Errorf("failed to write test signature file %q: %v", f.fullPath, err)
				}
			}
		}
		return nil
	}

	if err := os.MkdirAll(*tempDir, 0o777); err != nil {
		return err
	}
	// Get an absolute path to pass to MSBuild, because our working dirs may not be the same.
	// MSBuild in general will resolve paths relative to the csproj.
	absTemp, err := filepath.Abs(*tempDir)
	if err != nil {
		return err
	}
	propsFilePath := filepath.Join(absTemp, "Sign"+step+".props")
	if err := os.WriteFile(propsFilePath, []byte(sb.String()), 0o666); err != nil {
		return err
	}

	cmd := exec.CommandContext(
		ctx,
		"dotnet", "build", "Sign.csproj",
		"/p:SignFilesDir="+absTemp,
		"/p:FilesToSignPropsFile="+propsFilePath,
		"/t:AfterBuild",
		"/p:SignType="+*signType,
		"/bl:"+filepath.Join(absTemp, "Sign"+step+".binlog"),
		"/v:n",
	)
	cmd.Dir = *signingCsprojDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Running: %v", cmd)
	return cmd.Run()
}

type fileToSign struct {
	originalPath string
	fullPath     string
	authenticode string
	// This file is part of a zip payload, e.g. for macOS hardening.
	zip bool
	// macAppName for notarization.
	macAppName string
}

func (f *fileToSign) WriteMSBuildItem(w io.Writer) {
	fmt.Fprintf(w, "    <FilesToSign")
	fmt.Fprintf(w, ` Include="%v" Authenticode="%v"`, f.fullPath, f.authenticode)
	if f.zip {
		fmt.Fprintf(w, ` Zip="true"`)
	}
	if f.macAppName != "" {
		fmt.Fprintf(w, ` MacAppName="%v"`, f.macAppName)
	}
	fmt.Fprintf(w, " />\n")
}

// flatMapSlice sequentially maps each element of es to a slice using f and flattens the resulting
// slices. If any call to f returns an error, the error is returned immediately.
func flatMapSlice[E, R any](es []E, f func(E) ([]R, error)) ([]R, error) {
	var results []R
	for _, e := range es {
		rs, err := f(e)
		if err != nil {
			return nil, err
		}
		results = append(results, rs...)
	}
	return results, nil
}
