// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
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
