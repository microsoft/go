# `sign` and the Microsoft build of Go signing infrastructure

Most of the logic for signing (extracting files, repackaging, creating checksums) is implemented by this `sign` command.

The [`/eng/signing`](/eng/signing) directory contains the MSBuild project that `sign` invokes to run real signing.
The MSBuild project uses [MicroBuild Signing](https://dev.azure.com/devdiv/DevDiv/_wiki/wikis/DevDiv.wiki/650/MicroBuild-Signing) (internal Microsoft wiki link).

To see signing in action, go to [`/eng/pipeline/README.md`](/eng/pipeline/README.md) and follow the link for `microsoft-go`.

## Dry run

1. Create the directory `/eng/signing/tosign` and add the `.tar.gz` and `.zip` artifacts to sign.
    * Download artifacts from the `microsoft-go` pipeline, for example.
    * It's ok to skip downloading some artifacts. The signing process doesn't require all platforms to be present.
    * If you specify `-files`, you can use your own directory.
1. From the root of the repository, run `pwsh eng/run.ps1 sign -n`

The `-n` argument makes it a dry run: it extracts/repacks files in the same way it would if it were signing them, but no signing is done.
This doesn't involve .NET/MSBuild, so this is a good way for a developer to test changes to the signing logic.

See `pwsh eng/run.ps1 sign -h` for more options.

## Test signing

> [!NOTE]
> Test signing has not been observed to work.
> It has been documented for completeness, in case someone wants to try.

### Prerequisites

* Windows
* .NET Core SDK 8.0 or later.
    * [Download](https://dot.net/download)
* The signing plugin.
    1. Download the latest NuGet Package: https://devdiv.visualstudio.com/DevDiv/_artifacts/feed/MicroBuildToolset/NuGet/MicroBuild.Plugins.Signing
    1. Extract its contents (the file is a zip) to `%userprofile%\.nuget\packages\microbuild.plugins.signing\1.1.900`.
        * Optionally make the versioned dir's name match the version of the package you downloaded. It will be discovered dynamically, as a plugin, whether or not the version matches.

### Test signing run

1. Set up `tosign` as described in the dry run section.
1. From the root of the repository, run `pwsh eng/run.ps1 sign`

## Real signing

This can't be done from a dev machine.
It occurs in the `microsoft-go` pipeline, on a Windows machine.
See [`/eng/pipeline/README.md`](/eng/pipeline/README.md).

The invocation of `sign` can be found in [`/eng/pipeline/stages/sign-stage.yml`](/eng/pipeline/stages/sign-stage.yml).

### Parallel release signing

Three independent signing stages run on the existing Windows signing pool:

* Linux and source archives: create detached archive signatures and checksums.
* Windows archives: sign executables, repack, then create detached archive signatures and checksums.
* macOS archives: harden binaries, notarize, repack, then create detached archive signatures and checksums.

Each signing stage depends only on its platform's build stages, so it can start as soon as those
stages finish without waiting for other platforms. When signing an existing run, the signing stages
have no build dependencies and can all start immediately, subject to agent availability.

Each job downloads only its platform's builder artifacts. The source archive is produced by
the Linux amd64 builder, so it travels with the Linux artifacts. Signing remains batched within
each pass; the split removes cross-platform waits, not the dependencies within each archive.
Separate workspaces isolate the MSBuild intermediate files, signing payloads, and diagnostics.

Each flow publishes `Binaries Signed <os>` and `Signing diagnosis files <os> <attempt>`.
The final `Sign` stage waits for `Sign_linux`, `Sign_windows`, and `Sign_darwin` to succeed and
combines their outputs into the existing `Binaries Signed` artifact, rejecting duplicate filenames.
Downstream publishing keeps its existing dependency on `Sign` and its artifact download interface.

All signing jobs retain the existing MicroBuild production/test configuration and platform
certificate choices. The consolidation job does not sign files. Required output scanning and
SBOM generation remain enabled, including for the consolidated artifact.

To measure the change without rebuilding Go, queue the official pipeline from the branch
containing this change with `signExistingRunID` set to a completed build with all platform
artifacts. Use an approved pipeline and signing agents for real signing; local validation must
use dry-run or test signing. Compare overall release completion and the interval from the first
platform signing stage through the final `Sign` stage, including agent queueing, scanning, and
consolidation, rather than only the duration of the signing commands.
