# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

$ErrorActionPreference = 'Stop'

# Require PowerShell 6+, otherwise throw. Throw rather than "exit 1" so the error is reliably seen
# without $LASTEXITCODE handling on the caller. For example, the error will be easy to see even if
# this script is being dot-sourced in a user terminal.
#
# PowerShell 5 support could feasibly be added later. The scripts don't support it now because 5:
# * Only supports two "Join-Path" args.
# * Doesn't set OS detection automatic variables like "$IsWindows".
if ($host.Version.Major -lt 6) {
  Write-Host "Error: This script requires PowerShell 6 or higher; detected $($host.Version.Major)."
  Write-Host "See https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell"
  Write-Host "Or add 'pwsh' to the beginning of your command and try again."

  throw "Missing prerequisites; see logs above for details."
}

function Download-Stage0() {
  # We need Go installed in order to build Go, but our common build environment doesn't have it
  # pre-installed (or the right version pre-installed). This CI script installs a consistent version
  # of Go to handle this. This also makes it easier to locally repro issues in CI that involve a
  # specific version of Go. The downloaded copy of Go is called the "stage 0" version.
  $stage0_go_version = 'go1.25.0-1'

  # Source the install script so that we can use the PATH it assigns.
  $installScriptPath = Join-Path $PSScriptRoot "_util" "go-install.ps1"
  . $installScriptPath -Version $stage0_go_version
}

# Copied from https://github.com/dotnet/install-scripts/blob/49d5da7f7d313aa65d24fe95cc29767faef553fd/src/dotnet-install.ps1#L180-L197
function Invoke-WithRetry([ScriptBlock]$ScriptBlock, [int]$MaxAttempts = 3, [int]$SecondsBetweenAttempts = 1) {
  $Attempts = 0

  while ($true) {
    try {
      return & $ScriptBlock
    }
    catch {
      $Attempts++
      if ($Attempts -lt $MaxAttempts) {
        Start-Sleep $SecondsBetweenAttempts
      }
      else {
        throw
      }
    }
  }
}

function Invoke-CrossGoBlock([string] $GOOS, [string] $GOARCH, [ScriptBlock] $block) {
  $oldGOOS = $env:GOOS
  $oldGOARCH = $env:GOARCH

  try {
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    & $block
  } finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
  }
}

# Utility method to unzip a file to a specific path.
function Extract-Zip([string] $file, [string] $destination) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($file, $destination)
}

function Extract-TarGz([string] $file, [string] $destination) {
  & tar -C $destination -xzf $file
  if ($LASTEXITCODE) {
    throw "Error: 'tar' exit code $($LASTEXITCODE): failed to extract '$file' to '$destination'"
  }
}
