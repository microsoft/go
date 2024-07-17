# Release Studio infrastructure

This directory contains a .NET project that can download the infrastructure used by Microsoft to publish the Go binaries to official locations.
The infrastructure runs in PowerShell, but NuGet is used to acquire the tools.

## Getting tools locally

1. Run `dotnet restore` to get the package. If asked, use `dotnet restore --interactive` to set up auth.
1. Run `dotnet build` to get the package and let the package copy its scripts into `bin/*PublishingScripts`.
