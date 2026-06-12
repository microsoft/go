// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const rootImportPath = "github.com/microsoft/go/cryptobackend"

// Test that Unreachable panics.
func TestUnreachable(t *testing.T) {
	defer func() {
		if Enabled {
			if err := recover(); err == nil {
				t.Fatal("expected Unreachable to panic")
			}
		} else {
			if err := recover(); err != nil {
				t.Fatalf("expected Unreachable to be a no-op")
			}
		}
	}()
	Unreachable()
}

// Test that UnreachableExceptTests does not panic (this is a test).
func TestUnreachableExceptTests(t *testing.T) {
	UnreachableExceptTests()
}

func TestSubpackagesImportRoot(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	err = filepath.WalkDir(root, func(dir string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return err
		}
		if skipRootImportCheck(rel) {
			if rel == "." {
				return nil
			}
			return filepath.SkipDir
		}

		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return nil
		}

		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			if importsPackage(t, file, rootImportPath) {
				return nil
			}
		}

		t.Errorf("package %s does not import %q", filepath.ToSlash(rel), rootImportPath)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func skipRootImportCheck(rel string) bool {
	if rel == "." {
		return true
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	switch parts[0] {
	case "bbig", "fips140", "hash", "internal":
		return true
	}
	return false
}

func importsPackage(t *testing.T, file, importPath string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("parsing import path in %s: %v", file, err)
		}
		if path == importPath {
			return true
		}
	}
	return false
}
