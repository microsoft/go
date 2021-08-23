#!/usr/bin/env pwsh
param(
    # Name of OS to filter by
    [string]$OS,

    # Type of architecture to filter by
    [string]$Architecture,

    # Additional custom path filters
    [string[]]$Paths,

    # Additional args to pass to ImageBuilder
    [string]$OptionalImageBuilderArgs
)

# See https://github.com/dotnet/dotnet-docker/blob/main/build-and-test.ps1 when adding more
# configurability to this script. Follow the .NET Docker methodology when possible for consistency.

# Build the product images.
& $PSScriptRoot/common/build.ps1 `
    -OS $OS `
    -Architecture $Architecture `
    -Paths $Paths `
    -OptionalImageBuilderArgs $OptionalImageBuilderArgs
