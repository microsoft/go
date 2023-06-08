// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package archive is a library to create binary release zip and tar.gz files based on a completed
// Go build directory with contents that functionally match those at https://golang.org/dl/.
//
// The goal is to emulate the behavior of https://github.com/golang/build/tree/master/cmd/release in
// a way that integrates more easily into the Microsoft infrastructure in this repo.
package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CreateFromSource runs a Git command to generate an archive file from the Go source code at
// "source". If output is "", the archive is produced in the build directory inside the
// "eng/artifacts/bin" directory. A checksum file is also produced.
func CreateFromSource(source string, output string) error {
	fmt.Printf("---- Creating Go source archive (tarball) from '%v'...\n", source)

	if output == "" {
		output = filepath.Join(getBinDir(source), fmt.Sprintf("go.%v.src.tar.gz", getBuildID()))
	}

	// Ensure the target directory exists.
	archiveDir := filepath.Dir(output)
	if err := os.MkdirAll(archiveDir, os.ModeDir|os.ModePerm); err != nil {
		return err
	}

	// Use "^{tree}" to avoid Git including a global extended pax header. The commit it would list
	// is a temporary commit, and would only be confusing. See https://git-scm.com/docs/git-archive.
	cmd := exec.Command("git", "archive", "-o", output, "--prefix=go/", "HEAD^{tree}")
	cmd.Dir = source
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("---- Running command: %v\n", cmd.Args)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Printf("---- Creating checksum file...\n")
	if err := writeSHA256ChecksumFile(output); err != nil {
		return err
	}

	fmt.Printf("---- Pack complete.\n")
	return nil
}

// CreateFromBuild walks the Go build directory at "source" and produces an archive with the path
// "output". If output is "", CreateFromBuild produces a file in the build directory inside the
// "eng/artifacts/bin" directory. The output directory is created if it doesn't exist. This function
// also produces a checksum file for the archive in the same output directory.
//
// The inclusion of some files depends on the OS/ARCH. If output is specified, its filename must
// follow the pattern "*{GOOS}-{GOARCH}{extension}" so OS and ARCH can be detected. If output is not
// specified, the current Go runtime's OS and ARCH are used.
//
// If runtime.GOOS and runtime.GOARCH don't match the OS/ARCH of the output file name, the build
// directory is treated as a cross-compiled build of Go.
func CreateFromBuild(source, output string) error {
	fmt.Printf("---- Creating Go archive (zip/tarball) from '%v'...\n", source)

	if output == "" {
		output = DefaultBuildOutputPath(source, "", "")
	}

	// Ensure the target directory exists.
	archiveDir := filepath.Dir(output)
	_ = os.MkdirAll(archiveDir, os.ModeDir|os.ModePerm)

	// Pick an archiver based on target path extension.
	archiver, ext := createArchiveWriter(output)

	os, arch := getArchivePathRuntime(output, ext)
	fmt.Printf("Packing %q for %q %q\n", ext, os, arch)

	// Root-level directory entry names to include in the archive.
	includeNames := []string{
		"AUTHORS", "CONTRIBUTORS", "go.env", "LICENSE", "PATENTS", "VERSION",
		"api", "bin", "doc", "lib", "misc", "pkg", "src", "test",
	}

	// Full paths of dirs and files to skip adding. Use "os", not "runtime.GOOS", because that would
	// prevent this command from working across OSes. We may need to, for example, sign the contents
	// of windows-amd64 + windows-arm64 and then repack both zips on a single computer.
	skipPaths := []string{
		filepath.Join("pkg", "obj"),
		// Skip "cmd" in any GOOS_GOARCH directory, per upstream:
		// https://github.com/golang/build/blob/baa7b38160246c52ae4dc6ba5dcab4a24a4d59f8/cmd/release/release.go#L506-L521
		filepath.Join("pkg", os+"_"+arch, "cmd"),
		// Users don't need the API checker binary pre-built, per upstream:
		// https://github.com/golang/build/blob/baa7b38160246c52ae4dc6ba5dcab4a24a4d59f8/cmd/release/release.go#L493-L497
		filepath.Join("pkg", "tool", os+"_"+arch, "api"),
		filepath.Join("pkg", "tool", os+"_"+arch, "api.exe"),
	}

	hostOS := runtime.GOOS
	hostArch := runtime.GOARCH
	if hostOS != os || hostArch != arch {
		fmt.Printf("Handling cross-compile: %v-%v host to %v-%v target\n", hostOS, hostArch, os, arch)
		skipPaths = append(skipPaths, []string{
			// Don't include binaries that were built for the host toolchain.
			filepath.Join("pkg", hostOS+"_"+hostArch),
			filepath.Join("pkg", "tool", hostOS+"_"+hostArch),
			// Don't include the host binaries: the target binaries are in a subdir.
			filepath.Join("bin", "go"),
			filepath.Join("bin", "go.exe"),
			filepath.Join("bin", "gofmt"),
			filepath.Join("bin", "gofmt.exe"),
		}...)
	}

	// Figure out what the race detection syso (precompiled binary) is named for the current
	// os/arch. We want to exclude all race syso files other than this one.
	targetRuntimeRaceSyso := fmt.Sprintf("race_%v_%v.syso", os, arch)

	// Keep track of the last time we told the user something. Periodically send info about how much
	// data the script has processed to avoid appearing unresponsive.
	lastProgressUpdate := time.Now()

	// Keep track of target paths added to the archive (key) and the source path that it comes from
	// (value). This map ensures no target files are double-added.
	addedPaths := make(map[string]string)
	// Keep track of dir entries that have been added.
	addedDirs := make(map[string]struct{})

	err := filepath.WalkDir(source, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Failure accessing a path %q: %v\n", path, err)
			return err
		}

		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}

		// targetPath is where relPath should be placed in the output archive, if it belongs inside.
		targetPath := relPath

		// Walk every dir/file in the root of the repository.
		if relPath == "." {
			// Ignore the rest of the logic in this func by returning nil early.
			return nil
		}

		// If we're examining an entry in the repo root, only include specific files.
		if filepath.Dir(relPath) == "." {
			keep := false
			for _, include := range includeNames {
				if relPath == include {
					keep = true
				}
			}
			if matched, _ := filepath.Match("*.md", relPath); matched {
				keep = true
			}

			if !keep {
				// None of the inclusion rules matched, so stop walking. If this is a directory,
				// don't walk any of its children either.
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		} else {
			// Now we're deeper in the tree. Include everything by default and only exclude specific
			// files and directories.
			for _, skip := range skipPaths {
				if relPath == skip {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			// Include "bin/{OS}_{ARCH}/go" as "bin/go" if this is a cross-compilation build.
			if filepath.Dir(relPath) == filepath.Join("bin", os+"_"+arch) {
				targetPath = filepath.Join("bin", filepath.Base(relPath))
			}

			// Filter syso files in runtime/race. Note: intentionally leave all
			// runtime/race/internal syso files in place.
			if filepath.Dir(relPath) == filepath.Join("src", "runtime", "race") {
				// Skip race detection syso file if it doesn't match the target runtime.
				//
				// Ignore error: the only possible error is one that says the pattern is invalid (see
				// filepath.Match doc), which will never happen here because the pattern is a constant
				// string. (Do be careful if you change it!)
				isRaceSyso, _ := filepath.Match("race_*.syso", info.Name())
				if isRaceSyso && info.Name() != targetRuntimeRaceSyso {
					return nil
				}
			}
		}

		if info.IsDir() {
			// We want to continue the recursive search in this directory for more files, but we
			// don't necessarily want to add this dir to the archive. Return nil to continue.
			return nil
		}

		if relPath != targetPath {
			fmt.Printf("Archiving %#q as %#q\n", relPath, targetPath)
		}

		if otherSource, ok := addedPaths[targetPath]; ok {
			return fmt.Errorf(
				"adding archive file %#q from %#q, but target already added from %#q",
				targetPath, relPath, otherSource)
		}
		addedPaths[targetPath] = relPath

		// At this point, we know "path" is a file that should be included. Add it. Store everything
		// in a root "go" directory to match upstream Go archives.
		goTargetPath := filepath.Join("go", targetPath)
		if err := archiver.AddFile(path, goTargetPath); err != nil {
			return err
		}

		// Add all dirs that are ancestors of this target file. Even though explicitly added dirs
		// aren't necessary to create a valid archive file, upstream does this, so we do too. This
		// reduces the diff, e.g. when comparing results with tools like "tar -tf".
		dir := goTargetPath
		for {
			dir = filepath.Dir(dir)
			if dir == "." {
				break
			}
			if dir == "/" {
				return fmt.Errorf("unexpected rooted target path: %#q", goTargetPath)
			}

			if _, ok := addedDirs[dir]; ok {
				break
			}
			// Use root repository dir as a stand-in for any filesystem information. This is simpler
			// than reproducing the actual dir's path based on the target path, especially
			// considering the target path may not match up with a directory that actually exists.
			if err := archiver.AddFile(source, dir); err != nil {
				return err
			}
			addedDirs[dir] = struct{}{}
		}

		// If it's been long enough, log an update on our progress.
		now := time.Now()
		if now.Sub(lastProgressUpdate).Seconds() >= 5 {
			lastProgressUpdate = now
			fmt.Printf(
				"Archiving... (%8v kB uncompressed data archived)\n",
				archiver.ProcessedBytes()/1024.0,
			)
		}

		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf(
		"Complete! %v (%v kB uncompressed data archived)\n",
		output,
		archiver.ProcessedBytes()/1024.0,
	)

	if err := archiver.Close(); err != nil {
		return err
	}

	fmt.Printf("---- Creating checksum file...\n")
	if err := writeSHA256ChecksumFile(output); err != nil {
		return err
	}

	fmt.Printf("---- Pack complete.\n")
	return nil
}

// DefaultBuildOutputPath returns the default path to place the output archive given a built Go
// directory. Optionally takes os and arch, or detects their values from the environment and runtime
// if empty string.
func DefaultBuildOutputPath(source, os, arch string) string {
	if os == "" {
		os = runtime.GOOS
	}
	if arch == "" {
		arch = runtime.GOARCH
	}
	// Add "v6l" suffix to "arm" arch. More robust handling would be necessary if there were
	// multiple "arm" builds with GOARM=6 and GOARM=7, but there are not, and "arm64" obsoletes it.
	if arch == "arm" {
		arch += "v6l"
	}

	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}

	archiveName := fmt.Sprintf("go.%v.%v-%v%v", getBuildID(), os, arch, ext)
	return filepath.Join(getBinDir(source), archiveName)
}

// getBuildID returns BUILD_BUILDNUMBER if defined (e.g. a CI build). Otherwise, "dev".
func getBuildID() string {
	archiveVersion := os.Getenv("BUILD_BUILDNUMBER")
	if archiveVersion == "" {
		return "dev"
	}
	return archiveVersion
}

func getBinDir(source string) string {
	return filepath.Join(source, "..", "eng", "artifacts", "bin")
}

// getArchivePathRuntime takes a path like "go1.7.linux-amd64.tar.gz" and extension like ".tar.gz",
// and returns the os (linux) and arch (amd64). The "path" extension may have multiple '.'
// characters in it, so "ext" must be passed in explicitly or else the match would be ambiguous.
func getArchivePathRuntime(path string, ext string) (os string, arch string) {
	pathNoExt := path[0 : len(path)-len(ext)]
	firstRuntimeIndex := strings.LastIndex(pathNoExt, ".") + 1
	osArch := strings.Split(pathNoExt[firstRuntimeIndex:], "-")
	// "v6l" is added to the end of the "arm" arch filename, but is not part of the arch. Remove it.
	return osArch[0], strings.TrimSuffix(osArch[1], "v6l")
}

// writeSHA256ChecksumFile reads the content of the file at the given path into a SHA256 hasher, and
// writes the result to "{path}.sha256" in a format compatible with "sha256sum -v".
func writeSHA256ChecksumFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	checksum := sha256.New()
	_, err = io.Copy(checksum, file)
	if err != nil {
		return err
	}

	checksumHex := hex.EncodeToString(checksum.Sum(nil))
	fmt.Printf("Calculated %v\n", checksumHex)

	outputPath := path + ".sha256"
	checksumFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer checksumFile.Close()

	// Write the checksum in a format that "sha256sum -v" can work with. Use the base path of the
	// tarball (not full path, not relative path) because then "sha256sum -v" automatically works
	// when the file and the checksum file are downloaded to the same directory.
	fmt.Fprintf(checksumFile, "%v  %v\n", checksumHex, filepath.Base(path))

	fmt.Printf("Wrote checksum file %v\n", outputPath)
	return nil
}
