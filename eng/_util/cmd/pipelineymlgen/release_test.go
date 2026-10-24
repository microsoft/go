// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseBuilders(t *testing.T) {
	matrix := readPipeline(t, "stages/go-builder-matrix-stages.yml")
	innerloop := findMapping(t, matrix, "${{ if parameters.innerloop }}", "")
	branchCondition := "${{ if in(coalesce(variables['System.PullRequest.TargetBranch'], variables['Build.SourceBranch']), 'refs/heads/microsoft/main', 'microsoft/main') }}"
	main := mappingValue(findMapping(t, innerloop, branchCondition, ""), branchCondition)
	if len(main.Content) != 2 {
		t.Fatal("expected Linux and Windows release builders")
	}
	for i, os := range []string{"linux", "windows"} {
		builder := main.Content[i]
		requireValue(t, builder, "os", os)
		requireValue(t, builder, "arch", "amd64")
		requireValue(t, builder, "config", "release")
		if mappingValue(builder, "nosystemcrypto") != nil {
			t.Fatal("release builders must exercise the default crypto experiments")
		}
	}

	stage := readPipeline(t, "stages/run-stage.yml")
	job := findMapping(t, stage, "job", "${{ parameters.builder.id }}")
	condition := "${{ if eq(parameters.builder.config, 'release') }}"
	release := mappingValue(findMapping(t, job, condition, ""), condition)
	simulate := findMapping(t, release, "displayName", "Simulate RC VERSION")
	patch := findMapping(t, job, "displayName", "Apply patches")
	for _, step := range mappingValue(job, "steps").Content {
		if testSteps := mappingValue(step, "${{ else }}"); testSteps != nil {
			build := findMapping(t, testSteps, "displayName", "Build")
			if !strings.Contains(mappingValue(build, "pwsh").Value, "run-builder -build") {
				t.Fatal("release builders must use the usual toolchain build")
			}
			if patch.Line >= simulate.Line || simulate.Line >= build.Line {
				t.Fatal("VERSION must be written after patch application and before building")
			}
			return
		}
	}
	t.Fatal("missing default build and test steps")
}

func TestSimulateRCVersion(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	stage := readPipeline(t, "stages/run-stage.yml")
	step := findMapping(t, stage, "displayName", "Simulate RC VERSION")
	script := mappingValue(step, "pwsh").Value
	for _, tt := range []struct {
		name     string
		source   string
		existing string
		want     string
		wantErr  string
	}{
		{"current minor", "package goversion\nconst Version = 27\n", "", "go1.27rc1\n", ""},
		{"future minor CRLF", "package goversion\r\nconst Version = 28\r\n", "", "go1.28rc1\n", ""},
		{"existing version", "const Version = 27\n", "go1.27rc2\n", "go1.27rc2\n", "Refusing to overwrite"},
		{"invalid source", "package goversion\n", "", "", "Unable to determine"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			sourceDir := filepath.Join(root, "go", "src", "internal", "goversion")
			if err := os.MkdirAll(sourceDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sourceDir, "goversion.go"), []byte(tt.source), 0o644); err != nil {
				t.Fatal(err)
			}
			version := filepath.Join(root, "go", "VERSION")
			if tt.existing != "" {
				if err := os.WriteFile(version, []byte(tt.existing), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'\n"+script)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VERSION generation failed: %v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), tt.wantErr) {
				t.Fatalf("got %v\n%s; want error containing %q", err, out, tt.wantErr)
			}
			got, err := os.ReadFile(version)
			if tt.want == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("invalid source must not create VERSION: %v", err)
				}
			} else if err != nil || strings.ReplaceAll(string(got), "\r\n", "\n") != tt.want {
				t.Fatalf("VERSION = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}
