// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"archive/zip"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type archiveType int

const (
	// zipArchive is a Windows zip archive.
	zipArchive archiveType = iota
	// tarGzArchive is a macOS or Linux tar.gz archive.
	tarGzArchive
)

type archive struct {
	path string
	name string

	archiveType  archiveType
	archiveMacOS bool

	// workDir is a work dir absolute path that is only used for processing this archive.
	workDir string

	// repackedPath is a repackaged archive with signed content. Assigned upon completion.
	// Windows and macOS archives get repacked.
	repackedPath string
	// notarizedPath is a repacked archive that has also had the notarization ticket attached.
	// Assigned upon completion.
	notarizedPath string
}

const signingWorkingDirPrefix = "sign-work-"

func newArchive(p string) (*archive, error) {
	name := filepath.Base(p)
	a := archive{
		path: p,
		name: name,
	}
	if matchOrPanic("go*.zip", name) {
		a.archiveType = zipArchive
	} else if matchOrPanic("go*.tar.gz", name) {
		a.archiveType = tarGzArchive
	} else {
		return nil, fmt.Errorf("unknown archive type: %s", p)
	}

	if matchOrPanic("go*darwin*.tar.gz", name) {
		a.archiveMacOS = true
	}

	if err := os.MkdirAll(*tempDir, 0o777); err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(*tempDir, signingWorkingDirPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to create work directory: %v", err)
	}
	workDir, err = filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	a.workDir = workDir

	return &a, nil
}

// latestPath returns the path of the file that has the most signing steps applied to it. This
// allows for some generalization across platforms in later steps.
func (a *archive) latestPath() string {
	if a.notarizedPath != "" {
		return a.notarizedPath
	}
	if a.repackedPath != "" {
		return a.repackedPath
	}
	return a.path
}

func (a *archive) sigPath() string {
	return filepath.Join(a.workDir, a.name+".sig")
}

func (a *archive) macHardenPackPath() string {
	return filepath.Join(a.workDir, a.name+".ToHardenBundle.zip")
}

func (a *archive) macIndividualNotarizePackPath() string {
	return filepath.Join(a.workDir, a.name+".FilesToNotarize.zip")
}

// entrySignInfo returns signing details for a given file in the Go archive, or nil if the given
// file entry doesn't need to be signed.
func (a *archive) entrySignInfo(name string) *fileToSign {
	if a.archiveType == zipArchive {
		if strings.HasSuffix(name, ".exe") {
			return &fileToSign{
				originalPath: a.path,
				fullPath:     filepath.Join(a.workDir, "extract", name),
				authenticode: "Microsoft400",
			}
		}
	} else if a.archiveMacOS {
		if matchOrPanic("go/bin/*", name) ||
			matchOrPanic("go/pkg/tool/*/*", name) {

			return &fileToSign{
				originalPath: a.path,
				zip:          true,
			}
		}
	}
	return nil
}

// prepareEntriesToSign extracts files from the archive that need to be signed and returns a list
// of their extracted locations and details about how they should be signed.
func (a *archive) prepareEntriesToSign(ctx context.Context) ([]*fileToSign, error) {
	fail := func(err error) ([]*fileToSign, error) {
		return nil, fmt.Errorf("failed to extract file from %q: %v", a.path, err)
	}

	var results []*fileToSign

	if a.archiveType == zipArchive {
		log.Printf("Extracting files to sign from %q", a.path)
		zr, err := zip.OpenReader(a.path)
		if err != nil {
			return fail(err)
		}
		defer zr.Close()

		if err := eachZipEntry(zr, func(f *zip.File) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if f.FileInfo().IsDir() {
				return nil
			}
			if info := a.entrySignInfo(f.Name); info != nil {
				if err := withFileCreate(info.fullPath, func(fWriter *os.File) error {
					fReader, err := f.Open()
					if err != nil {
						return err
					}
					_, err = io.Copy(fWriter, fReader)
					return cmp.Or(err, fReader.Close())
				}); err != nil {
					return err
				}
				results = append(results, info)
			}
			return nil
		}); err != nil {
			return fail(err)
		}
	} else if a.archiveMacOS {
		// Store macOS files to sign in a zip. Zipping is needed for this platform specifically,
		// and the "Zip=true" feature mentioned in the doc only works when signing on a macOS
		// runtime, so we need to do it ourselves.
		// https://dev.azure.com/devdiv/DevDiv/_wiki/wikis/DevDiv.wiki/19841/Additional-Requirements-for-Signing-or-Notarizing-Mac-Files
		fts := &fileToSign{
			originalPath: a.path,
			fullPath:     a.macHardenPackPath(),
			authenticode: "MacDeveloperHarden",
		}
		log.Printf("Creating macOS file hardening bundle at %q", fts.fullPath)
		if err := withZipCreate(fts.fullPath, func(zw *zip.Writer) error {
			return a.extractMacOSEntriesToZip(ctx, zw)
		}); err != nil {
			return fail(err)
		}
		results = append(results, fts)
	}

	return results, nil
}

func (a *archive) prepareIndividualNotarize(ctx context.Context) ([]*fileToSign, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !a.archiveMacOS {
		return nil, nil
	}

	// Simply send the hardened zip back to the signing service for notarization.
	// Copy it first so that we can still access the hardened, pre-notarized files for diagnosis.
	if err := copyFile(a.macIndividualNotarizePackPath(), a.macHardenPackPath()); err != nil {
		return nil, err
	}

	return []*fileToSign{
		{
			originalPath: a.path,
			fullPath:     a.macIndividualNotarizePackPath(),
			authenticode: "8020", // Can't specify MacNotarize or MacAppName is not detected.
			macAppName:   "MicrosoftGo",
		},
	}, nil
}

func (a *archive) extractMacOSEntriesToZip(ctx context.Context, zw *zip.Writer) error {
	// Open tar.gz macOS archive to put files into the zip.
	writtenNames := make(map[string]struct{})
	return withTarGzOpen(a.path, func(tr *tar.Reader) error {
		return eachTarEntry(tr, func(header *tar.Header, r io.Reader) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if header.Typeflag != tar.TypeReg {
				return nil
			}
			if info := a.entrySignInfo(header.Name); info != nil {
				if !info.zip {
					return fmt.Errorf("unexpected file to sign directly rather than include in the zip batch: %q", header.Name)
				}

				base := filepath.Base(header.Name)
				if _, ok := writtenNames[base]; ok {
					return fmt.Errorf("duplicate file name in archive: %q", base)
				}
				writtenNames[base] = struct{}{}

				w, err := zw.CreateHeader(&zip.FileHeader{
					Name: base,
				})
				if err != nil {
					return err
				}
				_, err = io.Copy(w, r)
				return err
			}
			return nil
		})
	})
}

func (a *archive) repackSignedEntries(ctx context.Context) error {
	targetPath := filepath.Join(a.workDir, a.name+".WithSignedContent")
	if a.archiveType == zipArchive {
		log.Printf("Repacking signed content to %q", targetPath)
		if err := withZipOpen(a.path, func(zr *zip.ReadCloser) error {
			return withZipCreate(targetPath, func(zw *zip.Writer) error {
				return eachZipEntry(zr, func(f *zip.File) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					return a.writeZipRepackEntry(f, zw)
				})
			})
		}); err != nil {
			return err
		}
		a.repackedPath = targetPath
	} else if a.archiveMacOS {
		log.Printf("Repacking hardened content to %q", targetPath)
		// Open the original tar.gz for header info and to read unchanged files from.
		if err := withTarGzOpen(a.path, func(originalTR *tar.Reader) error {
			// Create the new tar.gz that we're assembling.
			return withTarGzCreate(targetPath, func(outTW *tar.Writer) error {
				// Open the zip payload we got back from the signing service.
				return withZipOpen(a.macIndividualNotarizePackPath(), func(zrc *zip.ReadCloser) error {
					// Iterate through the original tar.gz file to populate the target.
					return eachTarEntry(originalTR, func(hdr *tar.Header, originalR io.Reader) error {
						if err := ctx.Err(); err != nil {
							return err
						}
						return a.writeTarRepackEntry(hdr, originalR, &zrc.Reader, outTW)
					})
				})
			})
		}); err != nil {
			return err
		}
		a.repackedPath = targetPath
	}
	return nil
}

// writeZipRepackEntry looks at one entry in the original zip and creates a corresponding entry in
// the output zip. Reads signed entry content from the signed file on disk. If the file hasn't been
// signed, the content is read from the original zip.
func (a *archive) writeZipRepackEntry(original *zip.File, out *zip.Writer) error {
	w, err := out.CreateHeader(&zip.FileHeader{
		// Copy necessary original file metadata.
		Name:     original.Name,
		Method:   original.Method,
		Comment:  original.Comment,
		Modified: original.Modified,
		Extra:    original.Extra,
	})
	if err != nil {
		return err
	}
	var r io.ReadCloser
	// If we have a signed version of this file, read from that.
	// Otherwise, read from the original.
	if info := a.entrySignInfo(original.Name); info != nil {
		log.Printf("Replacing with signed version: %q", original.Name)
		r, err = os.Open(info.fullPath)
		if err != nil {
			return err
		}
	} else {
		r, err = original.Open()
		if err != nil {
			return err
		}
	}
	_, err = io.Copy(w, r)
	return cmp.Or(err, r.Close())
}

// writeTarRepackEntry looks at one entry in the original tar.gz and creates a corresponding entry
// in the output tar.gz. Reads signed/hardened entry content from signedPack. Otherwise, the entry
// content is copied from the original.
func (a *archive) writeTarRepackEntry(hdr *tar.Header, original io.Reader, signedPack *zip.Reader, out *tar.Writer) error {
	// Always start with header info from the original tar.gz even if we're going to replace the
	// file content. This means we don't need to worry about lost metadata due to the zip
	// round-trip.
	newHeader := &tar.Header{
		// Follow tar.Header documented compat guidance by copying over our selection of fields.
		Name:     hdr.Name,
		Linkname: hdr.Linkname,

		Size:  hdr.Size,
		Mode:  hdr.Mode,
		Uid:   hdr.Uid,
		Gid:   hdr.Gid,
		Uname: hdr.Uname,
		Gname: hdr.Gname,

		ModTime:    hdr.ModTime,
		AccessTime: hdr.AccessTime,
		ChangeTime: hdr.ChangeTime,
	}
	isFile := hdr.Typeflag == tar.TypeReg
	if info := a.entrySignInfo(hdr.Name); info != nil && isFile {
		log.Printf("Replacing with signed version: %q", hdr.Name)
		replacementFile, err := signedPack.Open(filepath.Base(hdr.Name))
		if err != nil {
			return err
		}
		defer replacementFile.Close()
		// Get the file size to prepare to copy.
		stat, err := replacementFile.Stat()
		if err != nil {
			return err
		}
		newHeader.Size = stat.Size()
		original = replacementFile
	}
	if err := out.WriteHeader(newHeader); err != nil {
		return fmt.Errorf(
			"failed to write header for %q: %v",
			newHeader.Name, err)
	}
	if isFile {
		_, err := io.Copy(out, original)
		if err != nil {
			return fmt.Errorf("failed to write %q: %v", newHeader.Name, err)
		}
	}
	// Call Flush to make sure our write was correct. We don't technically need to call Flush here
	// because the next WriteHeader will confirm that we e.g. wrote the correct number of bytes.
	// However, calling Flush ourselves lets us emit an error that mentions the bad filename
	// (rather than the next, unrelated filename).
	if err := out.Flush(); err != nil {
		return fmt.Errorf("failed to flush %q: %v", newHeader.Name, err)
	}
	return nil
}

func (a *archive) prepareBundleNotarize(ctx context.Context) ([]*fileToSign, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !a.archiveMacOS {
		return nil, nil
	}

	// Currently, we don't produce any macOS artifacts that can accept stapled notarization, like
	// app bundles, disk images, or installers.
	//
	// The executable binaries inside our tar.gz archive are already notarized by the earlier
	// "MacDeveloperHarden" step, and that's the best we can do. Individual file notarizations are
	// not stapled: they are stored by Apple and downloaded on demand.
	//
	// If we do produce notarizable artifacts in the future, add the logic here to pack them in a
	// zip and add logic to unpackBundleNotarize to extract them back out, if zip submission is
	// still a MicroBuild and/or ESRP requirement.
	return nil, nil
}

func (a *archive) unpackBundleNotarize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !a.archiveMacOS {
		return nil
	}

	return nil
}

func (a *archive) prepareArchiveSignatures(ctx context.Context) ([]*fileToSign, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Copy the archive file to have .sig suffix, e.g. "tar.gz" to "tar.gz.sig". The signing
	// process sends the "tar.gz.sig" file to get a signature, then replaces the "tar.gz.sig"
	// file's content in-place with the result. We need to preemptively make a renamed copy of the
	// file so we end up with both the original file and sig on the machine.
	log.Printf("Copying file for signature generation: %q -> %q", a.latestPath(), a.sigPath())
	if err := copyFile(a.sigPath(), a.latestPath()); err != nil {
		return nil, err
	}
	return []*fileToSign{
		{
			originalPath: a.path,
			fullPath:     a.sigPath(),
			authenticode: "LinuxSignManagedLanguageCompiler",
		},
	}, nil
}

func (a *archive) copyToDestination(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Create destination if it doesn't exist.
	if err := os.MkdirAll(*destinationDir, 0o777); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	log.Printf("Copying finished files to destination: %q", a.latestPath())
	if err := copyFile(filepath.Join(*destinationDir, a.name), a.latestPath()); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(*destinationDir, a.name+".sig"), a.sigPath()); err != nil {
		return err
	}
	return nil
}

func consolidateDiagnosticFiles() error {
	// Do as much as possible, accumulating errors to report to the user.
	var err error
	// Signing process logs.
	err = errors.Join(err, copyGlobFilesToDir(
		*consolidateDiagDir,
		filepath.Join(*signingCsprojDir, "*.log"),
		filepath.Join(*tempDir, "*.binlog"),
		filepath.Join(*tempDir, "*.props"),
	))
	// .NET diag data, for package versions etc.
	err = errors.Join(err, copyGlobFilesToDir(
		filepath.Join(*consolidateDiagDir, "obj"),
		filepath.Join(*signingCsprojDir, "obj", "*"),
	))

	// Signing working dirs. These contain the files actually sent to sign. Make
	// it clear that they're not production-ready files through the filename.
	cleanTempDir := filepath.Clean(*tempDir)
	err = errors.Join(err, withTarGzCreate(
		filepath.Join(*consolidateDiagDir, "sign-work-archives.nonproduction.tar.gz"),
		func(tw *tar.Writer) error {
			if err := filepath.WalkDir(cleanTempDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				// At the top level, only walk into working dirs.
				if d.IsDir() &&
					filepath.Dir(path) == cleanTempDir &&
					!strings.HasPrefix(d.Name(), signingWorkingDirPrefix) {

					return filepath.SkipDir
				}
				// Inside a given working dir, we are free to walk recursively.
				if d.IsDir() {
					return nil
				}
				// This is a file: archive it.
				df, err := d.Info()
				if err != nil {
					return err
				}
				// Basic sanity checks.
				if !filepath.IsLocal(path) {
					return fmt.Errorf("path %q is not a local path", path)
				}
				tarPath, ok := strings.CutPrefix(path, cleanTempDir+string(filepath.Separator))
				if !ok {
					return fmt.Errorf("path %q is not under temp dir %q", path, *tempDir)
				}
				tarPath = filepath.ToSlash(tarPath)

				err = tw.WriteHeader(&tar.Header{
					Name: tarPath,
					Size: df.Size(),
					Mode: 0o644,
				})
				if err != nil {
					return err
				}
				return copyFromFile(tw, path)
			}); err != nil {
				return err
			}
			return nil
		},
	))
	return err
}
