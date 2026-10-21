// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDownloadStage0Retry(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	dir := t.TempDir()
	utilities, err := os.ReadFile(filepath.Join("..", "..", "utilities.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "utilities.ps1"), utilities, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "_util"), 0o700); err != nil {
		t.Fatal(err)
	}
	const installer = `
param($Version, $InstallDir)
$global:attempts++
if ($global:attempts -le $global:failures) {
  throw "simulated download failure"
}
$env:PATH = $InstallDir + [System.IO.Path]::PathSeparator + $env:PATH
`
	if err := os.WriteFile(filepath.Join(dir, "_util", "go-install.ps1"), []byte(installer), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STAGE0_TEST_DIR", dir)
	const test = `
$ErrorActionPreference = 'Stop'
. (Join-Path $env:STAGE0_TEST_DIR 'utilities.ps1')
function Start-Sleep([int]$Seconds) {
  if ($Seconds -ne 30) { throw "Unexpected retry delay: $Seconds" }
  $global:sleeps++
}
$originalPath = $env:PATH
foreach ($failures in 0, 2, 3) {
  $global:failures = $failures
  $global:attempts = 0
  $global:sleeps = 0
  $env:PATH = $originalPath
  $failed = $false
  try {
    Download-Stage0
  } catch {
    if ($_ -notlike '*simulated download failure*') { throw }
    $failed = $true
  }
  $expectedAttempts = [Math]::Min($failures + 1, 3)
  if ($global:attempts -ne $expectedAttempts) { throw "Unexpected attempt count: $global:attempts" }
  if ($global:sleeps -ne ($expectedAttempts - 1)) { throw "Unexpected sleep count: $global:sleeps" }
  if ($failed -ne ($failures -eq 3)) { throw "Unexpected failure result: $failed" }
  if (!$failed) {
    $installDir = Join-Path $env:STAGE0_TEST_DIR 'artifacts' '_goStage0'
    if ($env:PATH -ne ($installDir + [System.IO.Path]::PathSeparator + $originalPath)) {
      throw "Installer PATH change was not preserved"
    }
  }
}
`
	cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", test)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stage-0 retry test failed: %v\n%s", err, out)
	}
}
