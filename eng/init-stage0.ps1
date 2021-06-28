# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

$ErrorActionPreference = 'Stop'

# Utility method to unzip a file to a specific path.
function Unzip-File([string] $file, [string] $destination) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($file, $destination)
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

# We need Go installed in order to build Go, but our common build environment
# doesn't have it pre-installed. This CI script installs a consistent, official
# version of Go to a directory in $env:USERPROFILE to handle this. This also
# makes it easier to locally repro issues in CI that involve a specific version
# of Go. The downloaded copy of Go is called the "stage 0" version.
#
# Ideally we could set up stage 0 inside the repository, rather than
# userprofile. Tracked by: https://github.com/microsoft/go/issues/12
$stage0_go_version = '1.16.5'
$stage0_go_sha256 = '0a3fa279ae5b91bc8c88017198c8f1ba5d9925eb6e5d7571316e567c73add39d'
$stage0_dir = "$env:USERPROFILE\.go-stage-0\$stage0_go_version"
$stage0_url = "https://golang.org/dl/go${stage0_go_version}.windows-amd64.zip"

$download_complete_indicator = "$stage0_dir\.downloaded"

if (-not (Test-Path $download_complete_indicator -PathType Leaf)) {
  Write-Host "Downloading stage 0 Go compiler and extracting to '$stage0_dir' ..."

  # Clear existing stage0 dir in case it's in a broken state.
  Remove-Item -Recurse -Force $stage0_dir -ErrorAction Ignore 
  New-Item -ItemType Directory $stage0_dir | Out-Null

  $go_tarball = "$stage0_dir\go.zip"

  Write-Host "Downloading from '$stage0_url' to '$go_tarball'..."
  Invoke-WithRetry -MaxAttempts 5 {
    (New-Object System.Net.WebClient).DownloadFile($stage0_url, $go_tarball)
  }

  Write-Host "Comparing checksum..."
  $actual_hash = (Get-FileHash $go_tarball -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual_hash -ne $stage0_go_sha256) {
    Write-Host "Hash of downloaded file '$go_tarball':"
    Write-Host "`t$actual_hash"
    Write-Host "doesn't match expected hash:"
    Write-Host "`t$stage0_go_sha256"
    Write-Host "Visit https://golang.org/dl/ to see the list of expected hashes."
    exit 1
  }

  Write-Host "Unzipping '$go_tarball' to '$stage0_dir'..."
  Unzip-File $go_tarball $stage0_dir
  Remove-Item "$go_tarball"

  New-Item -ItemType File "$download_complete_indicator" | Out-Null

  Write-Host "Done extracting stage 0 Go compiler to '$stage0_dir'"
}
