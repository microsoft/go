// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// createArchiveWriter determines what the given archive path's extension is, creates an archiver
// that writes to that archive path, and returns the archiver and detected extension.
//
// Uses strings.HasSuffix to detect archive type. An exact match against "filepath.Ext(path)"
// doesn't work because e.g. ".tar.gz" has two "." characters and only ".gz" would be detected. This
// is also why the function returns the extension: it's difficult to unambiguously determine the
// extension without simply checking each possibility like this function does.
func createArchiveWriter(path string) (a goArchiver, ext string) {
	switch {
	case strings.HasSuffix(path, ".tar.gz"):
		return newTarGzArchiver(path), ".tar.gz"
	case strings.HasSuffix(path, ".zip"):
		return newZipArchiver(path), ".zip"
	}
	panic(fmt.Errorf("unknown archive type: '%v'", path))
}

// goArchiver adds files to an archive.
type goArchiver interface {
	// AddFile adds a file from disk into the archive at the given path.
	AddFile(filePath string, archivePath string) error
	// Close closes the archive, completing it.
	Close() error
	// ProcessedBytes returns the number of bytes of file data that has been written into the
	// archive (before any reduction due to compression). It is intended to be used to show that
	// progress is happening, but not as a significant metric.
	ProcessedBytes() int64
}

// tarGzArchiver adds files to a ".tar.gz" archive.
type tarGzArchiver struct {
	file       *os.File
	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	processedByteTracker
}

func newTarGzArchiver(path string) *tarGzArchiver {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	gw := gzip.NewWriter(file)
	tw := tar.NewWriter(gw)

	return &tarGzArchiver{
		file:       file,
		gzipWriter: gw,
		tarWriter:  tw,
	}
}

func (a *tarGzArchiver) AddFile(filePath string, archivePath string) error {
	fileReader, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	stat, err := fileReader.Stat()
	if err != nil {
		return err
	}

	// Create and write the header for the next file.
	header, err := tar.FileInfoHeader(stat, filepath.Base(archivePath))
	if err != nil {
		return err
	}

	// tar.FileInfoHeader only takes base name, so set full path here. See FileInfoHeader doc.
	header.Name = archivePath

	if err := a.tarWriter.WriteHeader(header); err != nil {
		return err
	}

	n, err := io.Copy(a.tarWriter, fileReader)
	a.processedBytes += n
	return err
}

func (a *tarGzArchiver) Close() error {
	if err := a.tarWriter.Close(); err != nil {
		return err
	}
	if err := a.gzipWriter.Close(); err != nil {
		return err
	}
	return a.file.Close()
}

// zipArchiver adds files to a ".zip" archive.
type zipArchiver struct {
	file   *os.File
	writer *zip.Writer
	processedByteTracker
}

func newZipArchiver(path string) *zipArchiver {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	writer := zip.NewWriter(file)
	return &zipArchiver{
		file:   file,
		writer: writer,
	}
}

func (a *zipArchiver) AddFile(filePath string, archivePath string) error {
	archiveFileWriter, err := a.writer.Create(archivePath)
	if err != nil {
		return err
	}

	fileReader, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	n, err := io.Copy(archiveFileWriter, fileReader)
	a.processedBytes += n
	return err
}

func (a *zipArchiver) Close() error {
	if err := a.writer.Close(); err != nil {
		return err
	}
	return a.file.Close()
}

// processedByteTracker keeps track of the number of processed bytes in a way that implements the
// goArchiver interface. Embed processedByteTracker into a struct and change processedBytes over
// time to implement ProcessedBytes.
type processedByteTracker struct {
	processedBytes int64
}

func (a processedByteTracker) ProcessedBytes() int64 {
	return a.processedBytes
}
