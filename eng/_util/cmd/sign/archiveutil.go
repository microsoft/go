// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"archive/zip"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func eachZipEntry(r *zip.ReadCloser, f func(*zip.File) error) error {
	for _, file := range r.File {
		// Disallow absolute path, "..", etc.
		if !filepath.IsLocal(file.Name) {
			return fmt.Errorf("zip contains non-local path: %s", file.Name)
		}
		if err := f(file); err != nil {
			return err
		}
	}
	return nil
}

func eachTarEntry(r *tar.Reader, f func(*tar.Header, io.Reader) error) error {
	for {
		header, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		// Disallow absolute path, "..", etc.
		if !filepath.IsLocal(header.Name) {
			return fmt.Errorf("tar contains non-local path: %s", header.Name)
		}
		if err := f(header, r); err != nil {
			return err
		}
	}
}

func withFileOpen(path string, f func(*os.File) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return cmp.Or(f(file), file.Close())
}

func withZipOpen(path string, f func(*zip.ReadCloser) error) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	return cmp.Or(f(r), r.Close())
}

func withTarGzOpen(path string, f func(*tar.Reader) error) error {
	return withFileOpen(path, func(file *os.File) error {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		r := tar.NewReader(gz)
		return f(r)
	})
}

func withFileCreate(path string, f func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	return cmp.Or(f(file), file.Close())
}

func withZipCreate(path string, f func(*zip.Writer) error) error {
	return withFileCreate(path, func(file *os.File) error {
		w := zip.NewWriter(file)
		return cmp.Or(f(w), w.Close())
	})
}

func withTarGzCreate(path string, f func(*tar.Writer) error) error {
	return withFileCreate(path, func(file *os.File) error {
		gzw, err := gzip.NewWriterLevel(file, gzip.BestCompression)
		if err != nil {
			return err
		}
		tw := tar.NewWriter(gzw)
		return cmp.Or(f(tw), tw.Close(), gzw.Close())
	})
}

func copyFile(dst, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	return cmp.Or(copyToFile(dst, f), f.Close())
}

func copyToFile(path string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	return cmp.Or(err, f.Close())
}

func copyFromFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return cmp.Or(err, f.Close())
}

func copyGlobFilesToDir(dir string, globs ...string) error {
	for _, glob := range globs {
		files, err := filepath.Glob(glob)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := copyFile(filepath.Join(dir, filepath.Base(f)), f); err != nil {
				return err
			}
		}
	}
	return nil
}

// matchOrPanic returns whether name matches the pattern glob, or panics if pattern is invalid.
func matchOrPanic(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	if err != nil {
		panic(err)
	}
	return ok
}
