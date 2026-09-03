// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

//go:generate go test -run ^TestXCryptoDependencyIsSynced$ . -generate

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const rootImportPath = "github.com/microsoft/go/cryptobackend"
const xCryptoModulePath = "golang.org/x/crypto"

var generate = flag.Bool("generate", false, "update generated files")

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
	case "bbig", "fips140", "internal":
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

func TestXCryptoDependencyIsSynced(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if *generate {
		if err := syncXCryptoDependency(root); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := verifyXCryptoDependency(root); err != nil {
		t.Fatal(err)
	}
}

func syncXCryptoDependency(root string) error {
	xCryptoVersion, err := sourceXCryptoVersion(root)
	if err != nil {
		return err
	}
	if err := runGo(root, "mod", "edit", "-require="+xCryptoModulePath+"@"+xCryptoVersion); err != nil {
		return err
	}
	if err := runGo(root, "mod", "tidy"); err != nil {
		return err
	}
	return verifyXCryptoDependency(root)
}

func verifyXCryptoDependency(root string) error {
	xCryptoVersion, err := sourceXCryptoVersion(root)
	if err != nil {
		return err
	}
	backendVersion, ok, err := requiredModuleVersion(root, xCryptoModulePath)
	if err != nil {
		return fmt.Errorf("reading cryptobackend/go.mod: %w", err)
	}
	if !ok {
		return fmt.Errorf("cryptobackend/go.mod does not require %s; run \"go generate\" from cryptobackend", xCryptoModulePath)
	}
	if backendVersion != xCryptoVersion {
		return fmt.Errorf("cryptobackend/go.mod requires %s %s, want %s; run \"go generate\" from cryptobackend", xCryptoModulePath, backendVersion, xCryptoVersion)
	}
	tidyDiff, err := goModTidyDiff(root)
	if err != nil {
		return err
	}
	if tidyDiff != "" {
		return fmt.Errorf("cryptobackend module is not tidy; run \"go generate\" from cryptobackend\n%s", tidyDiff)
	}
	return nil
}

func sourceXCryptoVersion(root string) (string, error) {
	patchPath := filepath.Clean(filepath.Join(root, "..", "patches", "0001-Vendor-external-dependencies.patch"))
	data, err := os.ReadFile(patchPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", patchPath, err)
	}
	version, ok := requiredModuleVersionFromGoModPatch(data, xCryptoModulePath)
	if !ok {
		return "", fmt.Errorf("%s does not require %s", patchPath, xCryptoModulePath)
	}
	return version, nil
}

func requiredModuleVersionFromGoModPatch(patch []byte, modulePath string) (string, bool) {
	inGoMod := false
	for line := range strings.SplitSeq(string(patch), "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			inGoMod = strings.Contains(line, " a/src/go.mod ")
			continue
		}
		if !inGoMod {
			continue
		}
		if line == "" || (line[0] != '+' && line[0] != ' ') || strings.HasPrefix(line, "+++") {
			continue
		}
		fields := strings.Fields(line[1:])
		if len(fields) >= 2 && fields[0] == modulePath {
			return fields[1], true
		}
	}
	return "", false
}

func TestRequiredModuleVersionFromGoModPatch(t *testing.T) {
	const modulePath = "example.com/module"
	for _, test := range []struct {
		name  string
		line  string
		want  string
		found bool
	}{
		{"added", "+\texample.com/module v1.2.3", "v1.2.3", true},
		{"unchanged", " \texample.com/module v1.2.3", "v1.2.3", true},
		{"removed", "-\texample.com/module v1.2.3", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			patch := []byte("diff --git a/src/go.mod b/src/go.mod\n" + test.line + "\n")
			got, found := requiredModuleVersionFromGoModPatch(patch, modulePath)
			if got != test.want || found != test.found {
				t.Fatalf("requiredModuleVersionFromGoModPatch() = %q, %v; want %q, %v", got, found, test.want, test.found)
			}
		})
	}
}

type goModFile struct {
	Require []moduleRequirement
}

type moduleRequirement struct {
	Path    string
	Version string
}

func requiredModuleVersion(dir, modulePath string) (version string, ok bool, err error) {
	data, err := goOutput(dir, "mod", "edit", "-json")
	if err != nil {
		return "", false, err
	}
	var goMod goModFile
	if err := json.Unmarshal(data, &goMod); err != nil {
		return "", false, err
	}
	for _, require := range goMod.Require {
		if require.Path == modulePath {
			return require.Version, true, nil
		}
	}
	return "", false, nil
}

func runGo(dir string, args ...string) error {
	_, err := goOutput(dir, args...)
	return err
}

func goModTidyDiff(dir string) (string, error) {
	cmd := exec.Command("go", "mod", "tidy", "-diff")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	if len(out) > 0 {
		return string(out), nil
	}
	return "", fmt.Errorf("running go mod tidy -diff in %s: %v\n%s", dir, err, stderr.String())
}

func goOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return out, nil
}
