// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toolchaintest

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fileWithTLSMLKEM = `
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"slices"
)

var explicitCurves = flag.Bool("explicit-curves", false, "set CurvePreferences explicitly")

func main() {
	flag.Parse()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	config := &tls.Config{InsecureSkipVerify: true}
	if *explicitCurves {
		config.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519,
		}
	}
	clientErr := make(chan error, 1)
	go func() {
		defer client.Close()
		clientErr <- tls.Client(client, config).Handshake()
	}()

	stop := errors.New("ClientHello inspected")
	var groups []tls.CurveID
	err := tls.Server(server, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			groups = hello.SupportedCurves
			return nil, stop
		},
	}).Handshake()
	if !errors.Is(err, stop) {
		panic(fmt.Sprintf("server handshake: %v", err))
	}
	if err := <-clientErr; err == nil {
		panic("client handshake unexpectedly succeeded")
	}
	for _, group := range []tls.CurveID{
		tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519,
	} {
		fmt.Printf("%s=%t\n", group, slices.Contains(groups, group))
	}
}
`

func TestTLSMLKEMBuildDefault(t *testing.T) {
	t.Parallel()

	dir := filepath.Dir(writeFile(t, fileWithTLSMLKEM))
	for name, content := range map[string]string{
		"go.mod": "module example.com/tlsmlkem\n\ngo 1.26.0\n",
		"main_test.go": `package main
import "testing"
func TestClientHello(t *testing.T) { main() }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, noSystemCrypto := range []string{"0", "1"} {
		for _, command := range []string{"build", "test"} {
			for _, value := range []string{"", "0", "1", "other"} {
				t.Run("nosystemcrypto="+noSystemCrypto+"/"+command+"/MS_GOTLSMLKEM="+value, func(t *testing.T) {
					env := []string{
						"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOFIPS140=off",
						"GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH,
						"MS_GO_NOSYSTEMCRYPTO=" + noSystemCrypto,
						"MS_GOTLSMLKEM=" + value,
						"GODEBUG=tlsmlkem=1",
					}
					binary := outPath(t) + ".exe"
					args := []string{command, "-o", binary}
					if command == "test" {
						args = append(args, "-c")
					}
					execGoToolInDir(t, dir, false, env, append(args, ".")...)
					info, err := buildinfo.ReadFile(binary)
					if err != nil {
						t.Fatal(err)
					}
					var defaults string
					for _, setting := range info.Settings {
						if setting.Key == "DefaultGODEBUG" {
							defaults = setting.Value
						}
					}
					wantDefault := ""
					if value == "0" {
						wantDefault = "0"
					}
					checkTLSMLKEMDefault(t, defaults, wantDefault)

					for _, profile := range []string{"default", "off"} {
						for _, run := range []struct {
							name     string
							godebug  string
							explicit bool
						}{
							{name: "default"},
							{name: "disabled", godebug: "0"},
							{name: "enabled", godebug: "1"},
							{name: "explicit-curves", godebug: "0", explicit: true},
						} {
							t.Run(profile+"/"+run.name, func(t *testing.T) {
								debug := "fips140=off,ms_tlsx25519=1,tlssecpmlkem=1,ms_tlsprofile=" + profile
								want := value != "0"
								if run.godebug != "" {
									debug += ",tlsmlkem=" + run.godebug
									want = run.godebug != "0"
								}
								var args []string
								if command == "test" {
									args = append(args, "-test.run=^TestClientHello$")
								}
								if run.explicit {
									args = append(args, "-explicit-curves")
									want = true
								}
								cmd := exec.CommandContext(t.Context(), binary, args...)
								// Deliberately contradict the build-time value at runtime.
								runtimeValue := "0"
								if value == "0" {
									runtimeValue = "1"
								}
								cmd.Env = append(os.Environ(), "GODEBUG="+debug, "MS_GOTLSMLKEM="+runtimeValue)
								out, err := cmd.CombinedOutput()
								if err != nil {
									t.Fatalf("running binary: %v\n%s", err, out)
								}
								wantOutput := fmt.Sprintf("X25519MLKEM768=%t\nSecP256r1MLKEM768=%t\nSecP384r1MLKEM1024=%t\nX25519=true", want, want, want)
								if command == "test" {
									wantOutput += "\nPASS"
								}
								if got := strings.TrimSpace(string(out)); got != wantOutput {
									t.Errorf("ClientHello groups:\n%s\nwant:\n%s", got, wantOutput)
								}
							})
						}
					}
				})
			}
		}
	}
}

func TestTLSMLKEMDefaultPrecedence(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		version   string
		value     string
		mod       string
		work      string
		directive string
		fips      string
		want      string
	}{
		{name: "old-version", version: "1.23", want: "0"},
		{name: "old-version-env-one", version: "1.23", value: "1", want: "0"},
		{name: "module", value: "0", mod: "1", want: "1"},
		{name: "module-zero", value: "1", mod: "0", want: "0"},
		{name: "workspace", value: "0", mod: "0", work: "1", want: "1"},
		{name: "workspace-zero", value: "1", mod: "1", work: "0", want: "0"},
		{name: "directive", value: "0", mod: "0", work: "0", directive: "1", want: "1"},
		{name: "directive-zero", value: "1", mod: "1", work: "1", directive: "0", want: "0"},
		{name: "fips", value: "0", fips: "latest", want: "0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := fileWithoutCrypto
			if tt.directive != "" {
				source = "//go:debug tlsmlkem=" + tt.directive + "\n" + source
			}
			dir := filepath.Dir(writeFile(t, source))
			version := tt.version
			if version == "" {
				version = "1.26.0"
			}
			mod := "module example.com/tlsmlkem\n\ngo " + version + "\n"
			if tt.mod != "" {
				mod += "godebug tlsmlkem=" + tt.mod + "\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
				t.Fatal(err)
			}
			work := "off"
			if tt.work != "" {
				work = filepath.Join(dir, "go.work")
				content := "go " + version + "\nuse .\ngodebug tlsmlkem=" + tt.work + "\n"
				if err := os.WriteFile(work, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fips := tt.fips
			if fips == "" {
				fips = "off"
			}
			env := []string{
				"GOENV=off", "GOFLAGS=", "GOWORK=" + work,
				"GOFIPS140=" + fips, "MS_GOTLSMLKEM=" + tt.value,
			}
			out, _ := execGoToolInDir(t, dir, false, env, "list", "-f", "{{.DefaultGODEBUG}}", ".")
			checkTLSMLKEMDefault(t, out, tt.want)
			if tt.fips != "" && !strings.Contains(","+out+",", ",fips140=on,") {
				t.Errorf("DefaultGODEBUG = %q, want fips140=on", out)
			}
		})
	}
}

func TestTLSMLKEMGoEnv(t *testing.T) {
	t.Parallel()

	dir := filepath.Dir(writeFile(t, fileWithoutCrypto))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/tlsmlkem\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"GOENV=" + filepath.Join(dir, "goenv"), "GOWORK=off", "GOFLAGS=", "GOFIPS140=off", "MS_GOTLSMLKEM=",
	}
	execGoToolInDir(t, dir, false, env, "env", "-w", "MS_GOTLSMLKEM=0")
	out, _ := execGoToolInDir(t, dir, false, env, "env", "MS_GOTLSMLKEM")
	if out != "0" {
		t.Fatalf("go env MS_GOTLSMLKEM = %q, want 0", out)
	}
	out, _ = execGoToolInDir(t, dir, false, env, "env", "-changed", "-json")
	if !strings.Contains(out, `"MS_GOTLSMLKEM": "0"`) {
		t.Errorf("go env -changed -json did not report MS_GOTLSMLKEM=0:\n%s", out)
	}
	out, _ = execGoToolInDir(t, dir, false, env, "list", "-f", "{{.DefaultGODEBUG}}", ".")
	checkTLSMLKEMDefault(t, out, "0")
	out, _ = execGoToolInDir(t, dir, false, append(env, "MS_GOTLSMLKEM=1"), "list", "-f", "{{.DefaultGODEBUG}}", ".")
	checkTLSMLKEMDefault(t, out, "")
	execGoToolInDir(t, dir, false, env, "env", "-u", "MS_GOTLSMLKEM")
	out, _ = execGoToolInDir(t, dir, false, env, "list", "-f", "{{.DefaultGODEBUG}}", ".")
	checkTLSMLKEMDefault(t, out, "")
}

func checkTLSMLKEMDefault(t *testing.T, defaults, want string) {
	t.Helper()
	var got string
	for _, setting := range strings.Split(defaults, ",") {
		if key, value, ok := strings.Cut(setting, "="); ok && key == "tlsmlkem" {
			got = value
		}
	}
	if got != want {
		t.Errorf("DefaultGODEBUG = %q, want tlsmlkem value %q", defaults, want)
	}
}
