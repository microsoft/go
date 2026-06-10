# Installation

These are the installation methods available for the Microsoft build of Go.

This document allows you to choose an installation method based on your own needs.
For an opinionated guide about how to migrate an existing project from the official build of Go to the Microsoft build of Go in a Microsoft build environment, visit the [Migration Guide](MigrationGuide.md).

If you try to use the Microsoft build of Go and encounter problems, check the [Migration Guide](MigrationGuide.md) for solutions to commonly encountered issues.

> [!NOTE]
> Don't see an installation option that works for you? Let us know!
>
> Look for an existing issue with the [![](https://img.shields.io/github/labels/microsoft/go/Area-Acquisition)](https://github.com/microsoft/go/labels/Area-Acquisition) tag and leave a comment, or file a new issue.
> You can also get in contact using our other [support resources](/README.md#support).

## Docker Container Images

[microsoft/go-images](https://github.com/microsoft/go-images) maintains and documents container images that are available on Microsoft Artifact Registry.

## Azure Linux

The Azure Linux 3 `golang` package is the Microsoft build of Go.
Azure Linux is maintained at [microsoft/azurelinux](https://github.com/microsoft/azurelinux).

## Ubuntu

To install the Microsoft build of Go using an Ubuntu package, first set up the [Linux package repository for Microsoft Products](https://learn.microsoft.com/en-us/linux/packages).
Packages are available in the Ubuntu 22.04 and 24.04 repositories.

After the repository is added, install the Microsoft build of Go by running the following commands:

```bash
sudo apt-get update && sudo apt-get install msft-golang
```

## Azure Pipelines `GoTool@0` task

The [`GoTool@0`](https://learn.microsoft.com/azure/devops/pipelines/tasks/reference/go-tool-v0) Azure Pipelines build task supports installing the Microsoft build of Go.

To use it, set these inputs:

* `version`: the version of Go to install.
  * The task supports the version formats `1.X`, `1.X.Y`, and `1.X.Y-Z`, and if there is a partial match, it installs the latest matching version.
* `goDownloadUrl`: use `https://aka.ms/golang/release/latest` to select the Microsoft build of Go.

The resulting step in a yml-based Azure Pipeline looks like this:

```yml
- task: GoTool@0
  displayName: 'Install Go'
  inputs:
    version: '1.26'
    goDownloadUrl: 'https://aka.ms/golang/release/latest'
```

## GitHub Actions `setup-go` action

The [`actions/setup-go`](https://github.com/actions/setup-go) GitHub Action supports installing the Microsoft build of Go.

To use it, set these inputs:

* `go-version`: the version of Go to install.
  * The action supports the version formats `1.X`, `1.X.Y`, and `1.X.Y-Z`, and if there is a partial match, it installs the latest matching version.
  * The `stable` and `oldstable` aliases are not supported when installing the Microsoft build of Go.
* `go-download-base-url`: use `https://aka.ms/golang/release/latest` to select the Microsoft build of Go.

The resulting step in a GitHub Actions workflow looks like this:

```yml
- uses: actions/setup-go@v6
  with:
    go-version: '1.26'
    go-download-base-url: 'https://aka.ms/golang/release/latest'
```

## The `go-install.ps1` script

The [cross-platform `go-install.ps1` script](https://github.com/microsoft/go-infra/tree/main/goinstallscript) installs the Microsoft build of Go.
It can install specific versions or the latest releases.

If you use Azure Pipelines, try running the script in a [script step](https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/cmd-line-v2?view=azure-pipelines) and pass the `-AzurePipelinePath` argument to automatically set up `go` in the environment for future steps.

If you use GitHub Actions, pass the `-GitHubActionsPath` argument to automatically set up `go` in the environment for future steps.

## Binary archive

[Signed builds of Go](Downloads.md) are available as `zip` and `tar.gz` files.

After downloading the appropriate archive for your platform, extract it to the directory of your choice.
Use the `go` (or `go.exe`) executable in the `go/bin` directory.

## Build from source

To build the Microsoft build of Go from source with minimal system dependencies, we recommend that you use a [pre-patched source tarball](#pre-patched-source-tarball).
For example, a maintainer of a Microsoft build of Go package for a Linux distro might prefer this method.

If you expect to contribute to the Microsoft build of Go project in the future, you should [clone and build](#clone-and-build).

### Pre-patched source tarball

Each [microsoft/go GitHub release](https://github.com/microsoft/go/releases) includes a source tarball file ending in `.src.tar.gz`.
Download and extract that `.src.tar.gz` file, then use the [official Go build from source instructions](https://go.dev/doc/install/source).

> [!WARNING]
> The `Source code (zip)` and `Source code (tar.gz)` files that GitHub offers for download on the [microsoft/go releases page](https://github.com/microsoft/go/releases) are incomplete: they don't include the `go` submodule, and don't include a pointer to the correct upstream Go commit to use.
> Make sure to download the `.src.tar.gz` file.

### Clone and build

First, clone this repository using Git and check out the desired tag or commit.

If you want to contribute to the Microsoft build of Go project, read the [Developer Guide](DeveloperGuide.md).
It lists the steps we recommend to set up a Microsoft build of Go development environment, execute your first build, run the standard library test suite, and contribute a PR.
This creates a patched `go/` directory containing the `src/make.bash` script that can be used with the standard Go build from source instructions.

If you want to build on your own machine with minimal extra steps, run `pwsh eng/run.ps1 build --refresh`.
We use this script for CI builds.
See [eng/README.md](../../eng/README.md) for more details about `eng/run.ps1` and the prerequisites necessary to run it.

Once built, the Microsoft build of Go binary is found at `go/bin/go`.
