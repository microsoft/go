# Signing infrastructure

This directory contains the infrastructure used by Microsoft to sign the Go
binaries in internal builds. It is implemented using .NET, specifically
Microsoft.DotNet.SignTool from <https://github.com/dotnet/arcade>.

To see it in action, go to [`/eng/pipeline/README.md`](/eng/pipeline/README.md)
and follow the link for `microsoft-go`.

This infrastructure runs on Windows only.

## Running locally

1. Create the directory `tosign` and add `.tar.gz` and `.zip` artifacts.
1. Restore the tools:
   ```
   dotnet restore
   ```
   * You may need to add the MicroBuild feed into a NuGet.Config file:  
     `https://pkgs.dev.azure.com/dnceng/_packaging/MicroBuildToolset/nuget/v3/index.json`
1. Run a "test sign" job to exercise the tooling:
   ```
   dotnet msbuild /t:SignGoFiles /p:SignFilesDir=tosign /p:SigningType=test /bl
   ```
