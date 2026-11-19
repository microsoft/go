// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const testBuilderEnv = "GO_RUN_BUILDER_TEST_HELPER"

func TestMain(m *testing.M) {
	if builder := os.Getenv(testBuilderEnv); builder != "" {
		os.Args = []string{os.Args[0], "-n", "-test", "-builder", builder}
		main()
		return
	}
	os.Exit(m.Run())
}

func TestDistTestCommand(t *testing.T) {
	for _, tt := range []struct {
		builder string
		want    string
	}{
		{"linux-amd64-test", "[go/bin/go tool dist test]"},
		{"linux-amd64-race", "[go/bin/go tool dist test]"},
		{"linux-arm64-ssacheck", "[go/bin/go tool dist test -compile-only]"},
		{"linux-amd64-longtest", "[sudo --preserve-env go/bin/go tool dist test]"},
		{"windows-amd64-longtest", "[go/bin/go tool dist test]"},
	} {
		t.Run(tt.builder, func(t *testing.T) {
			cmd := exec.Command(os.Args[0])
			cmd.Env = append(os.Environ(), testBuilderEnv+"="+tt.builder)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("run-builder failed: %v\n%s", err, out)
			}
			want := "---- Dry run. Would have run test command: " + tt.want
			if !strings.Contains(string(out), want) {
				t.Errorf("run-builder output:\n%s\nwant %s", out, want)
			}
		})
	}
}
