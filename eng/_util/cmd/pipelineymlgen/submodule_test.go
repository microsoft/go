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

	"github.com/microsoft/go-infra/submodule"
	"go.yaml.in/yaml/v4"
)

func TestSubmoduleOverride(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	data, err := os.ReadFile("../../../../eng/pipeline/steps/init-submodule-task.yml")
	if err != nil {
		t.Fatal(err)
	}
	var template struct {
		Steps []yaml.Node
	}
	if err := yaml.Unmarshal(data, &template); err != nil {
		t.Fatal(err)
	}
	var conditional map[string][]struct {
		Pwsh string
	}
	if err := template.Steps[len(template.Steps)-1].Decode(&conditional); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, steps := range conditional {
		script = steps[0].Pwsh
	}
	if script == "" {
		t.Fatal("submodule override script not found")
	}

	for _, refType := range []string{"commit", "Gerrit ref", "missing ref", "invalid ref"} {
		t.Run(refType, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source with spaces")
			repo := filepath.Join(root, "outer")
			goDir := filepath.Join(repo, "go")
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
			for _, dir := range []string{source, repo, goDir} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				git(dir, "init")
				git(dir, "config", "user.name", "Test")
				git(dir, "config", "user.email", "test@example.com")
				git(dir, "config", "commit.gpgsign", "false")
			}
			write := func(path, contents string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(source, "file.txt"), "original\n")
			git(source, "add", ".")
			git(source, "commit", "-m", "Pinned commit")
			pinned := git(source, "rev-parse", "HEAD")
			write(filepath.Join(source, "upstream.txt"), "upstream change\n")
			git(source, "add", ".")
			git(source, "commit", "-m", "Upstream change")
			override := git(source, "rev-parse", "HEAD")
			gerritRef := "refs/changes/34/123434/2"
			git(source, "update-ref", gerritRef, override)

			git(goDir, "fetch", source, pinned)
			git(goDir, "checkout", "--detach", "FETCH_HEAD")
			git(repo, "config", "-f", ".gitmodules", "submodule.go.path", "go")
			git(repo, "config", "-f", ".gitmodules", "submodule.go.url", source)
			git(repo, "add", ".gitmodules", "go")
			git(repo, "commit", "-m", "Pin submodule")

			ref := override
			want := override
			wantErr := false
			switch refType {
			case "Gerrit ref":
				ref = gerritRef
			case "missing ref":
				ref, want, wantErr = "refs/changes/missing", pinned, true
			case "invalid ref":
				ref, want, wantErr = `missing; $(throw 'must not execute')`, pinned, true
			}
			cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", script)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "GO_SUBMODULE_REPOSITORY="+source, "GO_SUBMODULE_REF="+ref)
			out, err := cmd.CombinedOutput()
			if (err != nil) != wantErr {
				t.Fatalf("override error = %v, want error: %v\n%s", err, wantErr, out)
			}
			if got := git(repo, "rev-parse", ":go"); got != want {
				t.Fatalf("staged submodule = %s, want %s", got, want)
			}
			// Exercise the same init/reset sequence used by submodule-refresh before patching.
			if err := submodule.Init(repo, "", "", false); err != nil {
				t.Fatal(err)
			}
			if err := submodule.Reset(repo, goDir, true); err != nil {
				t.Fatal(err)
			}
			if got := git(goDir, "rev-parse", "HEAD"); got != want {
				t.Fatalf("refreshed submodule = %s, want %s", got, want)
			}
			patch := filepath.Join(root, "change.patch")
			write(patch, "diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-original\n+patched\n")
			git(goDir, "apply", "--index", patch)
			if got := git(goDir, "show", ":file.txt"); got != "patched" {
				t.Fatalf("patched content = %q", got)
			}
		})
	}
}
