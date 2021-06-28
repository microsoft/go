# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

<#
.DESCRIPTION
This script builds and runs a tool defined in a module in 'eng'.

To run a tool:
  run.ps1 <tool> [arguments...]

To list possible tools:
  run.ps1

Builds 'eng/<module>/cmd/<tool>/<tool>.go' and runs it using the list of
arguments. If necessary, this command automatically installs Go and downloads
the dependencies of the module.

Every tool accepts a '-h' argument to show tool usage help.
#>
param(
  [string] $tool
)

function Write-ToolList() {
  Write-Host "Possible tool commands:"
  foreach ($module in Get-ChildItem "$scriptroot\_*") {
    Write-Host "  Module $($module.Name):"
    foreach ($tool in Get-ChildItem "$module\cmd\*") {
      Write-Host "    $PSCommandPath $($tool.Name)"
    }
  }
  Write-Host ""
}

$scriptroot = $PSScriptRoot

if ($list) {
  Write-ToolList
  exit 0
}

if (-not $tool) {
  Write-Host "Error: No tool specified."
  (Get-Help $PSCommandPath).DESCRIPTION | Out-String | Write-Host
  Write-ToolList
  exit 1
}

# Find tool, then navigate up two directories to find the root of the module.
$tool_src = Get-Item "$scriptroot\_*\cmd\$tool"
$tool_module = $tool_src.Parent.Parent.FullName

$tool_output = "$scriptroot\artifacts\toolbin\$tool.exe"

if (-not $tool_src) {
  Write-Host "Error: Tool doesn't exist: '$tool'."
  Write-ToolList
  exit 1
}

. "$scriptroot/init-stage0.ps1"
$env:PATH += ";$stage0_dir/go/bin"

try {
  # Move into module so "go build" detects it and fetches dependencies.
  Push-Location $tool_module
  Write-Host "Building $tool_src\$tool.go -> $tool_output"
  & "$stage0_dir\go\bin\go" build -o "$tool_output" ".\cmd\$tool"
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build tool."
    exit 1
  }
  Write-Host "Building done."
} finally {
  Pop-Location
}

try {
  # Run tool from the root of the repo.
  Push-Location "$scriptroot\.."
  & "$tool_output" @args
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to run tool."
    exit 1
  }
} finally {
  Pop-Location
}