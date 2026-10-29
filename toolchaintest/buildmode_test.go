// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"debug/buildinfo"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxBuildMode(t *testing.T) {
	t.Parallel()
	source := writeFile(t, fileWithoutCrypto)

	for _, tt := range []struct {
		goarch string
		want   string
	}{
		{"386", "exe"},
		{"amd64", "pie"},
		{"arm", "exe"},
		{"arm64", "pie"},
		{"loong64", "pie"},
		{"mips", "exe"},
		{"mips64", "exe"},
		{"mips64le", "exe"},
		{"mipsle", "exe"},
		{"ppc64", "pie"},
		{"ppc64le", "pie"},
		{"riscv64", "exe"},
		{"s390x", "pie"},
	} {
		t.Run(tt.goarch, func(t *testing.T) {
			t.Parallel()
			env := []string{
				"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOFIPS140=off",
				"GOOS=linux", "GOARCH=" + tt.goarch, "CGO_ENABLED=0", "MS_GO_NOSYSTEMCRYPTO=1",
			}
			for _, mode := range []string{"implicit", "default", "exe"} {
				t.Run(mode, func(t *testing.T) {
					binary := outPath(t)
					args := []string{"build", "-o", binary}
					if mode != "implicit" {
						args = append(args, "-buildmode="+mode)
					}
					execGoTool(t, false, env, append(args, source)...)
					want := tt.want
					if mode == "exe" {
						want = "exe"
					}
					checkLinuxBuildMode(t, binary, want)
				})
			}
		})
	}
}

func TestLinuxBuildModeNative(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("requires linux/amd64 or linux/arm64")
	}
	t.Parallel()

	dir := filepath.Dir(writeFile(t, fileWithCrypto))
	for name, content := range map[string]string{
		"go.mod": "module example.com/buildmode\n\ngo 1.26.0\n",
		"main_test.go": `package main
import "testing"
func TestProgram(t *testing.T) { main() }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOFIPS140=off",
		"GOOS=linux", "GOARCH=" + runtime.GOARCH, "MS_GO_NOSYSTEMCRYPTO=0",
	}
	cgoEnabled, _ := execGoTool(t, false, env, "env", "CGO_ENABLED")
	for _, tt := range []struct {
		name, cgo, want string
		race            bool
	}{
		{"nocgo", "0", "pie", false},
		{"cgo", "1", "pie", false},
		{"race", "1", "exe", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cgo == "1" && cgoEnabled != "1" {
				t.Skip("requires cgo")
			}
			for _, command := range []string{"build", "test"} {
				t.Run(command, func(t *testing.T) {
					binary := outPath(t)
					args := []string{command, "-o", binary}
					if command == "test" {
						args = append(args, "-c")
					}
					if tt.race {
						args = append(args, "-race")
					}
					execGoToolInDir(t, dir, false, append(env, "CGO_ENABLED="+tt.cgo), append(args, ".")...)
					checkLinuxBuildMode(t, binary, tt.want)
					cmd := exec.CommandContext(t.Context(), binary)
					cmd.Env = append(os.Environ(), "GODEBUG=fips140=off")
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("running binary: %v\n%s", err, out)
					}
				})
			}
		})
	}
}

func checkLinuxBuildMode(t *testing.T, binary, want string) {
	t.Helper()
	f, err := elf.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	wantType := elf.ET_EXEC
	if want == "pie" {
		wantType = elf.ET_DYN
	}
	if f.Type != wantType {
		t.Errorf("ELF type = %v, want %v", f.Type, wantType)
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	for _, setting := range info.Settings {
		if setting.Key == "-buildmode" {
			mode = setting.Value
		}
	}
	if mode != want {
		t.Errorf("build info -buildmode = %q, want %q", mode, want)
	}
}
