# Installation

Visit the [Migration Guide](MigrationGuide.md) for guidance about how we
recommend migrating existing Go projects to use the Microsoft build of Go. This
guide also helps resolve commonly encountered issues.

> [!NOTE]
> Don't see an option that works for you? Let us know!  
> File a GitHub issue, or comment on an existing issue in this tag:
  [![](https://img.shields.io/github/labels/microsoft/go/Area-Acquisition)](https://github.com/microsoft/go/labels/Area-Acquisition)

## Docker Container Images

**[microsoft/go-images](https://github.com/microsoft/go-images)** maintains and
documents container images that are available on Microsoft Artifact Registry.

## Azure Linux

The **[Azure Linux](https://github.com/microsoft/azurelinux)** distribution
includes the `golang` package, a build of this fork of Go.

For more information about how to manage the `systemcrypto` migration from 1.24
to 1.25 in Azure Linux 3, see
[the `systemcrypto` section of the Migration Guide](MigrationGuide.md#migration-to-systemcrypto).

## Ubuntu

To install the Microsoft build of Go using an Ubuntu package, first set up the [Linux package repository for Microsoft Products](https://learn.microsoft.com/en-us/linux/packages).
Packages are available in the Ubuntu 22.04 and 24.04 repositories.

After the repository is added, install the Microsoft build of Go by running the following commands:

```bash
sudo apt-get update && sudo apt-get install msft-golang
```

## Azure Pipelines `GoTool@0` task

The [`GoTool@0`](https://learn.microsoft.com/azure/devops/pipelines/tasks/reference/go-tool-v0) Azure Pipelines build task supports installing the Microsoft build of Go.

To use it, set these parameters:

* `version`: the task supports the version formats `1.X`, `1.X.Y`, and `1.X.Y-Z`, and if there is a partial match, it installs the latest matching version. We recommend using the latest major version, currently `1.26`.
* `goDownloadUrl`: use `https://aka.ms/golang/release/latest` to select the Microsoft build of Go.

The resulting step in a yml-based Azure Pipeline looks like this:

```yml
- task: GoTool@0
  displayName: 'Install Go'
  inputs:
    version: '1.26'
    goDownloadUrl: 'https://aka.ms/golang/release/latest'
```

## GitHub Actions `setup-go`

The [`actions/setup-go`](https://github.com/actions/setup-go) GitHub Action supports installing the Microsoft build of Go.

To use it, set these parameters:

* `go-version`: the version of Go to install.
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

[Signed builds of Go](Downloads.md)
for several platforms are available as `zip` and `tar.gz` files.

## Build from source

### Pre-patched source tarball

[The microsoft/go GitHub releases](https://github.com/microsoft/go/releases)
include a source tarball file ending in `.src.tar.gz`. After downloading and
extracting the tar.gz file, build it using the
[upstream instructions](https://go.dev/doc/install/source).

> [!NOTE]
> The `zip` file that GitHub offers for download on the [microsoft/go releases page](https://github.com/microsoft/go/releases) is incomplete: it doesn't include the `go` submodule.
> Make sure to download the `.src.tar.gz` file instead, or [clone the repository using Git and set up the patched submodule](#clone-and-build).

### Clone and build

First, clone this repository using Git and check out the desired tag or commit.

If you want to contribute to the Microsoft build of Go project, read the [Developer Guide](DeveloperGuide.md).
It lists the steps we recommend to set up a Microsoft build of Go development environment, execute your first build, run the standard library test suite, and contribute a PR.

If you just want to build on your own machine, you may find it more
convenient to use the tools provided by the `eng/run.ps1` script. We use this
script for CI builds. See [eng/README.md](../../eng/README.md) for more details about
`eng/run.ps1` and other repository infrastructure.

Once built, the Microsoft build of Go binary is found at `go/bin/go`.
