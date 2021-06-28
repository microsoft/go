# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

<#
.DESCRIPTION
This script is a shortcut to run the "build" command in the "_core" module to
build Go. Run "eng\build.ps1 -h" to learn more.
#>

$ErrorActionPreference = 'Stop'

$scriptroot = $PSScriptRoot

& "$scriptroot\run.ps1" build @args
if ($LASTEXITCODE -ne 0) {
  Write-Error "Failed to build, exit code: $LASTEXITCODE"
}
