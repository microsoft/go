// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func readPipeline(t *testing.T, name string) *yaml.Node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "eng", "pipeline", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	return nil
}

func findMapping(t *testing.T, n *yaml.Node, key, value string) *yaml.Node {
	t.Helper()
	var matches []*yaml.Node
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if v := mappingValue(n, key); v != nil && v.Value == value {
			matches = append(matches, n)
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(n)
	if len(matches) != 1 {
		t.Fatalf("found %d mappings with %s=%q, want one", len(matches), key, value)
	}
	return matches[0]
}

func requireValue(t *testing.T, n *yaml.Node, key, want string) {
	t.Helper()
	got := mappingValue(n, key)
	if got == nil || got.Value != want {
		t.Fatalf("%s = %v, want %q", key, got, want)
	}
}

func TestDarwinFreshAgentRetry(t *testing.T) {
	builders := readPipeline(t, "stages/builders-to-stages.yml")
	unbroken := findMapping(t, builders, "${{ if not(builder.broken) }}", "")
	darwin := mappingValue(unbroken, "${{ if not(builder.broken) }}")
	darwin = mappingValue(darwin, "${{ if eq(builder.os, 'darwin') }}")
	if darwin == nil {
		t.Fatal("missing Darwin builder configuration")
	}
	testBuilders := mappingValue(darwin, "${{ if and(ne(builder.config, 'buildandpack'), not(startsWith(builder.config, 'codeql'))) }}")
	if testBuilders == nil {
		t.Fatal("fresh-agent retries must exclude builders without tests")
	}
	requireValue(t, testBuilders, "retryOnFreshAgent", "true")

	stage := readPipeline(t, "stages/run-stage.yml")
	requireValue(t, findMapping(t, stage, "name", "retryOnFreshAgent"), "default", "false")
	stages := mappingValue(stage.Content[0], "stages")
	jobs := mappingValue(stages.Content[0], "jobs")
	if len(jobs.Content) != 2 || mappingValue(jobs.Content[1], "${{ if parameters.retryOnFreshAgent }}") == nil {
		t.Fatal("expected only the original job and one compile-time-conditional retry job")
	}
	retry := findMapping(t, stage, "job", "${{ parameters.builder.id }}_test_retry")
	requireValue(t, retry, "dependsOn", "${{ parameters.builder.id }}")
	// Missing output (including setup failure), successful tests, and cancellation must not provision a VM.
	requireValue(t, retry, "condition", "and(succeeded(), eq(dependencies.${{ parameters.builder.id }}.outputs['retry.required'], 'true'))")
	if mappingValue(retry, "continueOnError") != nil {
		t.Fatal("a failed final retry must fail the stage")
	}

	request := findMapping(t, stage, "name", "retry")
	wantCondition := "and(succeeded(), ne(variables['TEST_BUILDER_SUCCESSFUL'], 'true'))"
	requireValue(t, request, "condition", wantCondition)
	publish := findMapping(t, stage, "displayName", "Publish toolchain for test retry")
	requireValue(t, publish, "condition", wantCondition)
	if publish.Line >= request.Line {
		t.Fatal("retry must only be requested after artifact publication succeeds")
	}
	snapshot := findMapping(t, stage, "displayName", "Preserve toolchain for test retry")
	first := findMapping(t, stage, "job", "${{ parameters.builder.id }}")
	fresh := findMapping(t, mappingValue(first, "steps"), "${{ if parameters.retryOnFreshAgent }}", "")
	initialTest := findMapping(t, mappingValue(fresh, "${{ if parameters.retryOnFreshAgent }}"), "template", "../steps/run-builder-tests.yml")
	initialAttempts := mappingValue(mappingValue(initialTest, "parameters"), "retryAttempts")
	if initialAttempts == nil || len(initialAttempts.Content) != 1 || initialAttempts.Content[0].Value != "1" {
		t.Fatal("build job must run exactly one provisional test attempt")
	}
	if snapshot.Line >= initialTest.Line || initialTest.Line >= publish.Line {
		t.Fatal("toolchain snapshot must precede tests, and publication must follow them")
	}

	steps := mappingValue(retry, "steps")
	final := findMapping(t, steps, "template", "../steps/run-builder-tests.yml")
	attempts := mappingValue(mappingValue(final, "parameters"), "retryAttempts")
	if attempts == nil || len(attempts.Content) != 1 || attempts.Content[0].Value != "FINAL" {
		t.Fatal("retry job must run exactly one final test attempt")
	}
	requireValue(t, mappingValue(final, "parameters"), "artifactSuffix", "-test-retry")
	restore := findMapping(t, retry, "displayName", "Restore toolchain for test retry")
	if restore.Line >= final.Line {
		t.Fatal("toolchain must be restored before the final test attempt")
	}
	for _, step := range steps.Content {
		if v := mappingValue(step, "pwsh"); v != nil && strings.Contains(v.Value, "run-builder -build") {
			t.Fatal("retry job must not rebuild the toolchain")
		}
	}
	variables := mappingValue(retry, "variables")
	artifact := findMapping(t, variables, "name", "retryToolchainArtifact")
	requireValue(t, artifact, "value", "$[ dependencies.${{ parameters.builder.id }}.outputs['retry.toolchainArtifact'] ]")
	download := findMapping(t, retry, "task", "DownloadPipelineArtifact@2")
	requireValue(t, mappingValue(download, "inputs"), "artifactName", "$(retryToolchainArtifact)")
	if download.Line >= restore.Line {
		t.Fatal("toolchain must be downloaded before restoration")
	}

	tests := readPipeline(t, "steps/run-builder-tests.yml")
	test := findMapping(t, tests, "name", "test_${{ attempt }}")
	provisional := mappingValue(test, "${{ if ne(attempt, 'FINAL') }}")
	requireValue(t, provisional, "ignoreLASTEXITCODE", "true")
	if mappingValue(test, "ignoreLASTEXITCODE") != nil {
		t.Fatal("final test attempt must propagate its exit code")
	}
	requireValue(t, mappingValue(mappingValue(test, "${{ if parameters.builder.nosystemcrypto }}"), "env"), "MS_GO_NOSYSTEMCRYPTO", "1")
	command := mappingValue(test, "pwsh").Value
	if !strings.Contains(command, "run-builder -test") || strings.Contains(command, "run-builder -build") {
		t.Fatal("shared test step must only run tests")
	}
}

func TestRetryTestCommand(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	tests := readPipeline(t, "steps/run-builder-tests.yml")
	test := findMapping(t, tests, "name", "test_${{ attempt }}")
	for _, tt := range []struct {
		name     string
		attempt  string
		testExit string
		wantExit int
	}{
		{"initial pass", "1", "0", 0},
		{"initial failure is provisional", "1", "1", 0},
		{"retry pass", "FINAL", "0", 0},
		{"retry failure is fatal", "FINAL", "1", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "eng"), 0o755); err != nil {
				t.Fatal(err)
			}
			stub := `
Write-Host ("ARGS:" + (($args | ForEach-Object { $_ }) -join '|'))
if ($env:RETRY_TEST_EXIT -eq '0') {
    Write-Host '##vso[task.setvariable variable=TEST_BUILDER_SUCCESSFUL]true'
}
exit ([int]$env:RETRY_TEST_EXIT)
`
			if err := os.WriteFile(filepath.Join(root, "eng", "run.ps1"), []byte(stub), 0o644); err != nil {
				t.Fatal(err)
			}
			command := strings.NewReplacer(
				"$(Build.SourcesDirectory)", filepath.ToSlash(root),
				"${{ parameters.builder.os }}", runtime.GOOS,
				"${{ parameters.builder.arch }}", runtime.GOARCH,
				"${{ parameters.builder.config }}", "test",
				"${{ parameters.builder.experiment }}", "systemcrypto",
				"${{ parameters.builder.fips }}", "True",
				"${{ attempt }}", tt.attempt,
			).Replace(mappingValue(test, "pwsh").Value)
			if tt.attempt == "FINAL" {
				// PowerShell@2 appends this unless ignoreLASTEXITCODE is true.
				command += "\nif (Test-Path variable:LASTEXITCODE) { exit $LASTEXITCODE }\n"
			}
			path := filepath.Join(root, "test.ps1")
			if err := os.WriteFile(path, []byte(command), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", path)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "RETRY_TEST_EXIT="+tt.testExit)
			out, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tt.wantExit {
				t.Fatalf("test step: %v\n%s; want exit %d", err, out, tt.wantExit)
			}
			output := string(out)
			for _, want := range []string{"|run-builder|-test|", "|-experiment|systemcrypto|", "|-fipsmode|"} {
				if !strings.Contains(output, want) {
					t.Fatalf("missing %q in command output:\n%s", want, output)
				}
			}
			success := strings.Contains(output, "variable=TEST_BUILDER_SUCCESSFUL]true")
			if success != (tt.testExit == "0") {
				t.Fatalf("incorrect test success signal:\n%s", output)
			}
		})
	}
}

func TestRetryToolchainArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Darwin toolchain archive scripts require Unix permissions and symlinks")
	}
	stage := readPipeline(t, "stages/run-stage.yml")
	snapshot := findMapping(t, stage, "displayName", "Preserve toolchain for test retry")
	restore := findMapping(t, stage, "displayName", "Restore toolchain for test retry")
	root := t.TempDir()
	original := filepath.Join(root, "original")
	retry := filepath.Join(root, "retry")
	staging := filepath.Join(root, "staging")
	for _, dir := range []string{filepath.Join(original, "go", "bin"), filepath.Join(retry, "go")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, contents string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(name, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(original, "go", "bin", "go"), "#!/bin/sh\nprintf original-toolchain", 0o755)
	write(filepath.Join(original, "go", "source.go"), "original source", 0o644)
	write(filepath.Join(original, "go", ".git"), "original git metadata", 0o644)
	write(filepath.Join(retry, "go", ".git"), "retry git metadata", 0o644)
	if err := os.Symlink("go", filepath.Join(original, "go", "bin", "tool-link")); err != nil {
		t.Fatal(err)
	}
	run := func(dir, script string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("archive script failed: %v\n%s", err, out)
		}
	}
	run(original, strings.ReplaceAll(mappingValue(snapshot, "bash").Value, "$(Build.ArtifactStagingDirectory)", staging))
	write(filepath.Join(original, "go", "source.go"), "modified by tests", 0o644)
	run(retry, strings.ReplaceAll(mappingValue(restore, "bash").Value, "$(Pipeline.Workspace)", staging))
	for name, want := range map[string]string{
		"source.go": "original source",
		".git":      "retry git metadata",
	} {
		got, err := os.ReadFile(filepath.Join(retry, "go", name))
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", name, got, err, want)
		}
	}
	cmd := exec.Command(filepath.Join(retry, "go", "bin", "tool-link"))
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "original-toolchain" {
		t.Fatalf("restored executable/symlink: output %q, error %v", out, err)
	}
}
