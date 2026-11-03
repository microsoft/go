// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if root := os.Getenv("GO_SUBMODULE_REFRESH_TEST_ROOT"); root != "" {
		os.Exit(runTestGit(root))
	}
	os.Exit(m.Run())
}

func runTestGit(root string) int {
	command := strings.Join(os.Args[1:], " ")
	logPath := filepath.Join(root, "git.log")
	previous, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(logPath, append(previous, []byte(command+"\n")...), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if command == "submodule update --init --depth 1" {
		failures, err := strconv.Atoi(os.Getenv("GO_SUBMODULE_REFRESH_TEST_FAILURES"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if strings.Count(string(previous), command+"\n") < failures {
			fmt.Fprintln(os.Stderr, "simulated fetch failure")
			return 128
		}
	}
	if command == os.Getenv("GO_SUBMODULE_REFRESH_TEST_FAIL_COMMAND") {
		return 128
	}
	if command == "rev-parse --show-toplevel" {
		dir, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(dir)
	}
	return 0
}

func TestRefreshRetriesOnlyInit(t *testing.T) {
	oldShallow, oldSkipPatch := *shallow, *skipPatch
	t.Cleanup(func() {
		*shallow, *skipPatch = oldShallow, oldSkipPatch
	})
	*shallow = true

	for _, tt := range []struct {
		name        string
		failures    int
		failCommand string
		skipPatch   bool
		wantInit    int
		wantReset   int
		wantApply   int
		wantErr     bool
	}{
		{name: "success", wantInit: 1, wantReset: 1, wantApply: 1},
		{name: "transient failure", failures: 1, wantInit: 2, wantReset: 1, wantApply: 1},
		{name: "last attempt succeeds", failures: 2, wantInit: 3, wantReset: 1, wantApply: 1},
		{name: "attempts exhausted", failures: 3, wantInit: 3, wantErr: true},
		{name: "reset failure", failCommand: "submodule update --init -f", wantInit: 1, wantReset: 1, wantErr: true},
		{name: "patch failure", failCommand: "apply --index --whitespace=nowarn", wantInit: 1, wantReset: 1, wantApply: 1, wantErr: true},
		{name: "skip patches after retry", failures: 1, skipPatch: true, wantInit: 2, wantReset: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			git := filepath.Join(t.TempDir(), "git")
			if runtime.GOOS == "windows" {
				git += ".exe"
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err := copyFile(executable, git); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(git, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "go"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".git-go-patch"), []byte(`{"SubmoduleDir":"go","PatchesDir":"patches"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", filepath.Dir(git))
			t.Setenv("GO_SUBMODULE_REFRESH_TEST_ROOT", root)
			t.Setenv("GO_SUBMODULE_REFRESH_TEST_FAILURES", strconv.Itoa(tt.failures))
			t.Setenv("GO_SUBMODULE_REFRESH_TEST_FAIL_COMMAND", tt.failCommand)
			*skipPatch = tt.skipPatch

			if err := refresh(root); (err != nil) != tt.wantErr {
				t.Fatalf("refresh error = %v, want error: %v", err, tt.wantErr)
			}
			commands, err := os.ReadFile(filepath.Join(root, "git.log"))
			if err != nil {
				t.Fatal(err)
			}
			for command, want := range map[string]int{
				"submodule update --init --depth 1\n": tt.wantInit,
				"submodule update --init -f\n":        tt.wantReset,
				"apply --index --whitespace=nowarn\n": tt.wantApply,
			} {
				if got := strings.Count(string(commands), command); got != want {
					t.Errorf("command %q ran %d times, want %d", command, got, want)
				}
			}
		})
	}
}

func TestRefreshRef(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is not installed")
	}
	oldRef, oldOrigin := *ref, *origin
	oldShallow, oldSkipPatch := *shallow, *skipPatch
	t.Cleanup(func() {
		*ref, *origin = oldRef, oldOrigin
		*shallow, *skipPatch = oldShallow, oldSkipPatch
	})
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	t.Setenv("GIT_AUTHOR_NAME", "Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")

	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(t.TempDir(), "source with spaces")
	git(t.TempDir(), "init", source)
	git(source, "config", "core.autocrlf", "false")
	write(filepath.Join(source, "file.txt"), "original\n")
	git(source, "add", ".")
	git(source, "commit", "-m", "Pinned revision")
	pinned := git(source, "rev-parse", "HEAD")
	write(filepath.Join(source, "upstream.txt"), "upstream change\n")
	git(source, "add", ".")
	git(source, "commit", "-m", "Override revision")
	override := git(source, "rev-parse", "HEAD")
	gerritRef := "refs/changes/34/123434/2"
	git(source, "update-ref", gerritRef, override)

	for _, tt := range []struct {
		name          string
		existing      bool
		gerrit        bool
		defaultOrigin bool
		full          bool
		skipPatch     bool
		missing       bool
	}{
		{name: "fresh SHA"},
		{name: "fresh Gerrit ref", gerrit: true},
		{name: "existing SHA", existing: true},
		{name: "existing Gerrit ref", existing: true, gerrit: true},
		{name: "default origin", defaultOrigin: true},
		{name: "full fetch", full: true},
		{name: "skip patches", skipPatch: true},
		{name: "fresh missing ref", missing: true},
		{name: "existing missing ref", existing: true, missing: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			sub := filepath.Join(root, "go")
			git(root, "init")
			git(root, "config", "-f", ".gitmodules", "submodule.go.path", "go")
			git(root, "config", "-f", ".gitmodules", "submodule.go.url", source)
			git(root, "add", ".gitmodules")
			git(root, "update-index", "--add", "--cacheinfo", "160000", pinned, "go")
			git(root, "commit", "-m", "Pin submodule")
			write(filepath.Join(root, ".git-go-patch"), `{"SubmoduleDir":"go","PatchesDir":"patches"}`)
			if err := os.Mkdir(filepath.Join(root, "patches"), 0o700); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(root, "patches", "0001-change.patch"),
				"diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-original\n+patched\n")
			existingOrigin := filepath.Join(root, "unavailable-origin")
			if tt.existing {
				git(root, "submodule", "update", "--init")
				git(sub, "remote", "set-url", "origin", existingOrigin)
				write(filepath.Join(sub, "file.txt"), "local change\n")
				write(filepath.Join(sub, "untracked.txt"), "local file\n")
			}
			if !tt.defaultOrigin {
				// Explicit -origin must not fetch from the pinned submodule source.
				git(root, "config", "-f", ".gitmodules", "submodule.go.url", existingOrigin)
				git(root, "config", "submodule.go.url", existingOrigin)
			}
			*ref, *origin = override, source
			*shallow, *skipPatch = !tt.full, tt.skipPatch
			if tt.gerrit {
				*ref = gerritRef
			}
			if tt.defaultOrigin {
				*origin = ""
			}
			if tt.missing {
				*ref = "refs/changes/missing"
			}
			trace := filepath.Join(root, "git.trace")
			t.Setenv("GIT_TRACE", filepath.ToSlash(trace))
			err := refresh(root)
			if (err != nil) != tt.missing {
				t.Fatalf("refresh error = %v, want error: %v", err, tt.missing)
			}
			wantCommit := override
			if tt.missing {
				wantCommit = pinned
			}
			if got := git(root, "rev-parse", ":go"); got != wantCommit {
				t.Fatalf("staged revision = %s, want %s", got, wantCommit)
			}
			checkContent := func(want string) {
				t.Helper()
				got, err := os.ReadFile(filepath.Join(sub, "file.txt"))
				if err != nil || string(got) != want {
					t.Fatalf("file.txt = %q, %v; want %q", got, err, want)
				}
			}
			if tt.missing {
				if tt.existing {
					checkContent("local change\n")
					if got := git(sub, "rev-parse", "HEAD"); got != pinned {
						t.Fatalf("failed fetch changed HEAD to %s", got)
					}
				}
			} else {
				if got := git(sub, "rev-parse", "HEAD"); got != override {
					t.Fatalf("HEAD = %s, want %s", got, override)
				}
				wantOrigin := source
				if tt.existing {
					wantOrigin = existingOrigin
				}
				if got := git(sub, "remote", "get-url", "origin"); got != wantOrigin {
					t.Fatalf("origin = %q, want %q", got, wantOrigin)
				}
				if !tt.existing {
					if got := git(sub, "rev-parse", "--is-shallow-repository"); got != strconv.FormatBool(!tt.full) {
						t.Fatalf("unexpected shallow state: %s", got)
					}
				}
				if tt.skipPatch {
					checkContent("original\n")
				} else {
					checkContent("patched\n")
				}
				if _, err := os.Stat(filepath.Join(sub, "untracked.txt")); !os.IsNotExist(err) {
					t.Fatalf("untracked file not cleaned: %v", err)
				}
				*ref, *origin, *skipPatch = "", "", false
				if err := refresh(root); err != nil {
					t.Fatal(err)
				}
				checkContent("patched\n")
				if got := git(sub, "rev-parse", "HEAD"); got != override {
					t.Fatalf("subsequent refresh changed HEAD to %s", got)
				}
			}
			traceData, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			wantFetches := 1
			if tt.missing {
				wantFetches = 3
			}
			if got := strings.Count(string(traceData), "built-in: git fetch "); got != wantFetches {
				t.Fatalf("fetch count = %d, want %d\n%s", got, wantFetches, traceData)
			}
			if !tt.missing && !tt.existing {
				git(root, "restore", "--staged", "--", "go")
				if err := refresh(root); err != nil {
					t.Fatalf("restore pinned revision: %v", err)
				}
				if got := git(sub, "rev-parse", "HEAD"); got != pinned {
					t.Fatalf("restored HEAD = %s, want %s", got, pinned)
				}
				checkContent("patched\n")
			}
		})
	}
}
