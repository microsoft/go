# Copyright (c) Microsoft Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

$srcDir = $env:BUILD_SOURCESDIRECTORY
# Microsoft-specific engineering tools and configuration.
$engDirectory = Join-Path $srcDir "eng"
# Microsoft-specific GitHub and GitHub Actions configuration.
$dotGitHubDirectory = Join-Path $srcDir ".github"
# Official build artifacts, downloaded from the build job that completed earlier.
$downloadedArtifactsDirectory = Join-Path $env:BUILD_ARTIFACTSTAGINGDIRECTORY "artifacts"

# Remove verison number from the artifact path to make path-based issue suppression more reliable.
foreach ($item in Get-ChildItem -Directory $downloadedArtifactsDirectory)
{
  # Handle e.g.
  # C:\artifacts\go1.22-cd589c8-20230809.2.linux-arm64.tar.gz.extracted\
  # C:\artifacts\go1.22.3-20230809.2.windows-amd64.zip.extracted\
  # C:\artifacts\go1.22.0-20230813.14.src.tar.gz.extracted\
  if ($item.Name.StartsWith("go") -and $item.Name.EndsWith(".extracted"))
  {
    $oldName = $item.FullName
    $newName = $item.FullName -replace '\\go.+\.([\w-]+)\.(tar\.gz|zip)\.extracted\\', '\go.$1.$2.extracted\'
    if ($oldName -ne $newName)
    {
      Write-Host "Renaming '$oldName' to '$newName'"
      Move-Item $oldName $newName
    }
  }
}

# Create a file for PoliCheck's ListFile option. The extension must be ".txt", and this file must
# contain full paths, one per line, with no duplicates. The list should contain each microsoft/go
# file but no upstream files. Sort and print it for debug purposes.
$policheckFileList = (New-TemporaryFile).FullName + ".txt"
(
  Get-ChildItem -File -Recurse $srcDir `
  | Where-Object {
    # Submodule directory with upstream code.
    -not $_.FullName.StartsWith((Join-Path $srcDir "go")) -and `
    # SDL NuGet packages: ignore, not part of our code.
    -not $_.FullName.StartsWith((Join-Path $srcDir ".packages")) } `
  | ForEach-Object { $_.FullName } | Sort-Object `
) -join "`r`n" > $policheckFileList

Write-Host "--- List of files in PoliCheck file list:"
Get-Content $policheckFileList | Write-Host
Write-Host "---"

& "$PSScriptRoot\..\..\common\sdl\execute-all-sdl-tools.ps1" `
  -SourceToolsList @(
    @{ Name="credscan"; Scenario="source" }
  ) `
  -ArtifactToolsList @(
    @{ Name="credscan"; Scenario="artifacts" }
  ) `
  -CrScanAdditionalRunConfigParams @(
    "SuppressionsPath < $engDirectory\compliance\Guardian\CredScanSuppressions.json"
    "SuppressAsError < false"
  ) `
  -CustomToolsList @(
    @{
      Name="binskim"
      Args=@(
        # Point binskim at the artifact directory. Pass everything to binskim and let it decide what
        # it needs to scan. For more information about the glob format, see
        # https://dev.azure.com/securitytools/SecurityIntegration/_wiki/wikis/Guardian/1378/Glob-Format
        #
        # Exclude "testdata" binaries because they are only used during testing, they do not pass
        # "binskim" for various reasons, and they are checked into the upstream Go repository.
        #
        # Exclude infra dependencies in ".gdn" dir. We are not distributing these.
        #
        # Exclude all ".exe" files. BinSkim strongly expects PDB files for each one, but they don't
        # exist for Go. See https://github.com/microsoft/go/issues/114
        "Target < f|$downloadedArtifactsDirectory\**;-|**\testdata\*;-|.gdn\**;-|**\*.exe"
        "ConfigPath < $engDirectory\compliance\Guardian\BinSkimConfig.xml"
      )
    }
    @{
      Name="codesign"
      Args=@(
        # Point codesign at the right location to find the artifacts that we've signed. However, we do
        # not yet produce any artifacts that CodeSign knows how to verify, so don't fail if CodeSign
        # fails to find anything.
        "TargetDirectory < $downloadedArtifactsDirectory"
        "targetFiles < f|**\*.dll;f|**\*.exe"
        "failIfNoTargetsFound < false"
      )
    }
    # Only point PoliCheck at directories we control, not directories from the upstream repo.
    @{
      Name="policheck"
      Args=@(
        # Target's default is ".", but we need to pass nothing instead. The Target and ListFile
        # PoliCheck args are mutually exclusive.
        "Target"
        "ListFile < $policheckFileList"
      )
    }
  ) `
  @args
