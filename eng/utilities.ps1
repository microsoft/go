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

function Get-Stage0GoRoot() {
  # We need Go installed in order to build Go, but our common build environment doesn't have it
  # pre-installed. This CI script installs a consistent, official version of Go to a directory in
  # $HOME to handle this. This also makes it easier to locally repro issues in CI that involve a
  # specific version of Go. The downloaded copy of Go is called the "stage 0" version.
  $stage0_go_version = '1.22.6'

  $proc_arch = ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture).ToString().ToLowerInvariant()
  if ($IsWindows) {
    switch ($proc_arch) {
      'x64' {
        $stage0_go_sha256 = '6023083a6e4d3199b44c37e9ba7b25d9674da20fd846a35ee5f9589d81c21a6a'
        $stage0_go_suffix = 'windows-amd64.zip'
      }
      'arm64' {
        $stage0_go_sha256 = '7cf55f357ba8116cd3bff992980e20a704ba451b3dab341cf1787b133d900512'
        $stage0_go_suffix = 'windows-arm64.zip'
      }
      Default { throw "Unable to match Windows '$proc_arch' to an architecture supported by the Microsoft scripts to build Go." }
    }
  } elseif ($IsLinux) {
    switch ($proc_arch) {
      'x64' {
        $stage0_go_sha256 = '999805bed7d9039ec3da1a53bfbcafc13e367da52aa823cb60b68ba22d44c616'
        $stage0_go_suffix = 'linux-amd64.tar.gz'
      }
      'arm64' {
        $stage0_go_sha256 = 'c15fa895341b8eaf7f219fada25c36a610eb042985dc1a912410c1c90098eaf2'
        $stage0_go_suffix = 'linux-arm64.tar.gz'
      }
      Default { throw "Unable to match Linux '$proc_arch' to an architecture supported by the Microsoft scripts to build Go." }
    }
  } elseif ($IsMacOS) {
    switch ($proc_arch) {
      'x64' {
        $stage0_go_sha256 = '98a09c085b4c385abae7d35b9155195d5e584d14988347ac7f18e4cbe3b5ef3d'
        $stage0_go_suffix = 'darwin-amd64.tar.gz'
      }
      'arm64' {
        $stage0_go_sha256 = '1163be1998835a13f00dfc869a8e3cdebf86984ad41ff2fff43e35ac2a0d8344'
        $stage0_go_suffix = 'darwin-arm64.tar.gz'
      }
      Default { throw "Unable to match macOS '$proc_arch' to an architecture supported by the Microsoft scripts to build Go." }
    }
  } else {
    throw "Current OS/Platform is not supported by the Microsoft scripts to build Go."
  }
  $stage0_url = "https://golang.org/dl/go${stage0_go_version}.${stage0_go_suffix}"

  # Ideally we could set up stage 0 inside the repository, rather than
  # userprofile. Tracked by: https://github.com/microsoft/go/issues/12
  $stage0_dir = Join-Path $HOME ".go-stage-0" $stage0_go_version

  # A file that indicates that this version of the stage 0 Go toolset has already been installed.
  $download_complete_indicator = Join-Path $stage0_dir ".downloaded-$stage0_go_sha256"

  if (-not (Test-Path $download_complete_indicator -PathType Leaf)) {
    Write-Host "Downloading stage 0 Go compiler and extracting to '$stage0_dir' ..."

    # Clear existing stage0 dir in case it's in a broken state.
    Remove-Item -Recurse -Force $stage0_dir -ErrorAction Ignore 
    New-Item -ItemType Directory $stage0_dir | Out-Null

    $go_tarball = Join-Path $stage0_dir "go.$stage0_go_suffix"

    Write-Host "Downloading from '$stage0_url' to '$go_tarball'..."
    Invoke-WithRetry -MaxAttempts 5 {
      (New-Object System.Net.WebClient).DownloadFile($stage0_url, $go_tarball)
    }

    Write-Host "Comparing checksum..."
    $actual_hash = (Get-FileHash $go_tarball -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual_hash -ne $stage0_go_sha256) {
      Write-Host ""
      Write-Host "Error: hash of downloaded file '$go_tarball' doesn't match expected value:"
      Write-Host "Actual:   $actual_hash"
      Write-Host "Expected: $stage0_go_sha256"
      Write-Host "Visit https://golang.org/dl/ to see the list of expected hashes."

      throw "Checksum mismatch. See logs above for details."
    }

    Write-Host "Extracting '$go_tarball' to '$stage0_dir'..."
    if ($go_tarball.EndsWith(".zip")) {
      Extract-Zip $go_tarball $stage0_dir
    } elseif ($go_tarball.EndsWith(".tar.gz")) {
      Extract-TarGz $go_tarball $stage0_dir
    }
    Remove-Item "$go_tarball"

    New-Item -ItemType File "$download_complete_indicator" | Out-Null

    Write-Host "Done extracting stage 0 Go compiler to '$stage0_dir'"
  }

  # Return GOROOT: contains "bin/go".
  return Join-Path $stage0_dir "go"
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
