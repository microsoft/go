# Signing infrastructure

This directory contains the infrastructure used by Microsoft to sign the Go
binaries in internal builds. It uses
[MicroBuild Signing](https://dev.azure.com/devdiv/DevDiv/_wiki/wikis/DevDiv.wiki/650/MicroBuild-Signing)
(internal Microsoft wiki link).

To see it in action, go to [`/eng/pipeline/README.md`](/eng/pipeline/README.md)
and follow the link for `microsoft-go`.

This infrastructure runs on Windows only.

## Running locally

1. Create the directory `tosign` and add `.tar.gz` and `.zip` artifacts.
1. Install the plugin:
   1. Download the latest https://devdiv.visualstudio.com/DevDiv/_artifacts/feed/MicroBuildToolset/NuGet/MicroBuild.Plugins.Signing
   1. Extract it to `%userprofile%\.nuget\microbuild.plugins.signing\1.1.900`.
      * Optionally make the last dir match the version of the package. It will be discovered dynamically, as a plugin, whether or not it matches.
1. Run a "test sign" build locally to exercise the tooling:
   ```
   dotnet build /p:SignFilesDir=tosign /p:SignType=test /p:MicroBuild_SigningEnabled=true /bl
   ```
