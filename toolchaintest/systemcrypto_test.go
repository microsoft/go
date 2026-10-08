// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var goExecutable = flag.String("go", "", "Go executable to test; defaults to the running toolchain's GOROOT/bin/go")

const fileWithCrypto = `
package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	fmt.Println(sha256.Sum256([]byte("Hello, World!")))
}
`

const fileWithoutCrypto = `
package main

import (
	"fmt"
)

func main() {
	fmt.Println("Hello, World!")
}
`

func goToolPath(t *testing.T) string {
	t.Helper()
	path := *goExecutable
	if path == "" {
		name := "go"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path = filepath.Join(runtime.GOROOT(), "bin", name)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func execGoTool(t *testing.T, allowFail bool, env []string, args ...string) (string, bool) {
	t.Helper()
	return execGoToolInDir(t, "", allowFail, env, args...)
}

func execGoToolInDir(t *testing.T, dir string, allowFail bool, env []string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), goToolPath(t), args...)
	cmd.Dir = dir
	for _, entry := range cmd.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GOROOT", "GODEBUG", "GOTRACEBACK":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "GOTOOLCHAIN=local")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	sout := strings.TrimSpace(string(out))
	if err != nil {
		if allowFail {
			return sout, false
		}
		t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return sout, true
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	name := "main.go"
	if strings.Contains(content, "testing") {
		name = "main_test.go"
	}
	name = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func outPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "out")
}

func TestSystemCryptoNoCgoChecks(t *testing.T) {
	t.Parallel()

	cryptoFile := writeFile(t, fileWithCrypto)

	tt := []struct {
		goos   string
		goarch string
	}{
		{"linux", "386"},
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"linux", "loong64"},
		{"linux", "ppc64le"},
		{"linux", "riscv64"},
		{"linux", "s390x"},
		{"linux", "arm"},
		{"freebsd", "amd64"},
		{"freebsd", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "386"},
		{"windows", "amd64"},
		{"windows", "arm64"},
	}
	for _, tc := range tt {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			t.Parallel()
			env := []string{"CGO_ENABLED=0", "GOOS=" + tc.goos, "GOARCH=" + tc.goarch, "MS_GO_NOSYSTEMCRYPTO=0"}
			if out, ok := execGoTool(t, true, env, "build", "-o", outPath(t), cryptoFile); !ok {
				t.Fatalf("expected success, got failure: %s", out)
			}
		})
	}
}

func TestSystemCryptoFreeBSDNoCgo(t *testing.T) {
	t.Parallel()

	cryptoFile := writeFile(t, fileWithCrypto)
	env := []string{"CGO_ENABLED=0", "GOOS=freebsd", "GOARCH=386", "MS_GO_NOSYSTEMCRYPTO=0"}
	out, ok := execGoTool(t, true, env, "build", "-o", outPath(t), cryptoFile)
	if ok {
		t.Fatal("expected failure, got success")
	}
	if !strings.Contains(out, "Using system crypto on FreeBSD requires CGO_ENABLED=1 on architectures other than amd64 and arm64") {
		t.Fatalf("expected cgo requirement error, got: %s", out)
	}
}

func TestSystemCryptoFIPS(t *testing.T) {
	// Test different go commands with GODEBUG=fips140=on
	// to exercise the ms_skipfipscheck build tag.
	t.Parallel()
	env := []string{"GODEBUG=fips140=on"}

	cryptoFile := writeFile(t, fileWithCrypto)
	nonCryptoFile := writeFile(t, fileWithoutCrypto)

	// Build should always succeed given that the go toolchain
	// is built with the ms_skipfipscheck build tag.
	execGoTool(t, false, env, "build", "-o", outPath(t), cryptoFile)
	execGoTool(t, false, env, "build", "-o", outPath(t), nonCryptoFile)

	// Run should always succeed if the target go package
	// doesn't use crypto.
	execGoTool(t, false, env, "run", nonCryptoFile)

	// Run may or may not fail if the target go package uses crypto,
	// because while the toolchain was built with ms_skipfipscheck, the
	// target program was not. Failure depends on system crypto mode
	// and presence of system-provided crypto, and it can't be tested here.
}

func TestSystemCryptoDefault(t *testing.T) {
	t.Parallel()
	cryptoFile := writeFile(t, fileWithCrypto)

	// Add here all the OS/ARCH combinations that enable systemcrypto by default.
	type testCase struct {
		goos   string
		goarch string
	}
	test := []testCase{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"freebsd", "amd64"},
		{"freebsd", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
		{"windows", "arm64"},
	}
	for _, tt := range test {
		t.Run(fmt.Sprintf("%s_%s", tt.goos, tt.goarch), func(t *testing.T) {
			t.Parallel()
			out := outPath(t)
			env := []string{"CGO_ENABLED=0", "GOOS=" + tt.goos, "GOARCH=" + tt.goarch, "MS_GO_NOSYSTEMCRYPTO=0"}
			execGoTool(t, false, env, "build", "-o", out, cryptoFile)
			// Check that the binary has the correct settings.
			settings, _ := execGoTool(t, false, nil, "version", "-m", out)
			if !strings.Contains(settings, "microsoft_systemcrypto=1") {
				t.Errorf("expected microsoft_systemcrypto=1 in settings, got %v", settings)
			}
		})
	}
}

func TestSystemCryptoDisabled(t *testing.T) {
	t.Parallel()
	cryptoFile := writeFile(t, fileWithCrypto)

	tests := []struct {
		goos   string
		goarch string
	}{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"freebsd", "amd64"},
		{"freebsd", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
		{"windows", "arm64"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.goos, tt.goarch), func(t *testing.T) {
			t.Parallel()
			out := outPath(t)
			env := []string{"CGO_ENABLED=0", "GOOS=" + tt.goos, "GOARCH=" + tt.goarch, "MS_GO_NOSYSTEMCRYPTO=1"}
			execGoTool(t, false, env, "build", "-o", out, cryptoFile)
			settings, _ := execGoTool(t, false, nil, "version", "-m", out)
			if strings.Contains(settings, "microsoft_systemcrypto=1") {
				t.Errorf("expected microsoft_systemcrypto=1 not to be in settings, got %v", settings)
			}
		})
	}
}

func TestSystemCryptoBuildTag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/systemcrypto-tag\n\ngo 1.27\n",
		"always.go":         "package main\n",
		"with_system.go":    "//go:build goexperiment.systemcrypto\n\npackage main\n",
		"with_openssl.go":   "//go:build goexperiment.opensslcrypto\n\npackage main\n",
		"with_cng.go":       "//go:build goexperiment.cngcrypto\n\npackage main\n",
		"with_darwin.go":    "//go:build goexperiment.darwincrypto\n\npackage main\n",
		"without_system.go": "//go:build !goexperiment.systemcrypto\n\npackage main\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name      string
		env       []string
		wantFiles []string
		badFiles  []string
	}{
		{
			name:      "linux_supported",
			env:       []string{"GOOS=linux", "GOARCH=amd64", "MS_GO_NOSYSTEMCRYPTO=0"},
			wantFiles: []string{"with_system.go", "with_openssl.go"},
			badFiles:  []string{"without_system.go", "with_cng.go", "with_darwin.go"},
		},
		{
			name:      "darwin_supported",
			env:       []string{"GOOS=darwin", "GOARCH=arm64", "MS_GO_NOSYSTEMCRYPTO=0"},
			wantFiles: []string{"with_system.go", "with_darwin.go"},
			badFiles:  []string{"without_system.go", "with_openssl.go", "with_cng.go"},
		},
		{
			name:      "windows_supported",
			env:       []string{"GOOS=windows", "GOARCH=386", "MS_GO_NOSYSTEMCRYPTO=0"},
			wantFiles: []string{"with_system.go", "with_cng.go"},
			badFiles:  []string{"without_system.go", "with_openssl.go", "with_darwin.go"},
		},
		{
			name:      "freebsd_supported",
			env:       []string{"GOOS=freebsd", "GOARCH=amd64", "MS_GO_NOSYSTEMCRYPTO=0"},
			wantFiles: []string{"with_system.go", "with_openssl.go"},
			badFiles:  []string{"without_system.go", "with_cng.go", "with_darwin.go"},
		},
		{
			name:      "disabled",
			env:       []string{"GOOS=linux", "GOARCH=amd64", "MS_GO_NOSYSTEMCRYPTO=1"},
			wantFiles: []string{"without_system.go"},
			badFiles:  []string{"with_system.go", "with_openssl.go", "with_cng.go", "with_darwin.go"},
		},
		{
			name:      "unsupported",
			env:       []string{"GOOS=plan9", "GOARCH=amd64", "MS_GO_NOSYSTEMCRYPTO=0"},
			wantFiles: []string{"without_system.go"},
			badFiles:  []string{"with_system.go", "with_openssl.go", "with_cng.go", "with_darwin.go"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, _ := execGoToolInDir(t, dir, false, tt.env, "list", "-f", "{{.GoFiles}}", ".")
			for _, wantFile := range tt.wantFiles {
				if !strings.Contains(out, wantFile) {
					t.Fatalf("go list .GoFiles = %q, want %s", out, wantFile)
				}
			}
			for _, badFile := range tt.badFiles {
				if strings.Contains(out, badFile) {
					t.Fatalf("go list .GoFiles = %q, did not want %s", out, badFile)
				}
			}
		})
	}
}
