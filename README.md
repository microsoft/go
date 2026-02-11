# The Microsoft build of Go

Go is an open source programming language that makes it easy to build simple, reliable, and efficient software.
The Microsoft build of Go, maintained in the [microsoft/go repository](https://github.com/microsoft/go), contains the infrastructure Microsoft uses to build a modified version of the Go toolset.

Unless otherwise noted, the Go source files are distributed under the BSD-style license found in the LICENSE file.

This project is not involved in producing the [official binary distributions of Go](https://go.dev/dl/).

## Why does this fork exist?

This repository produces a modified version of Go that:

* Builds programs that are compliant with internal Microsoft policies by default.
* Can be used to build FIPS 140 compliant applications.
  * See [eng/doc/fips](eng/doc/fips) for more information about this feature and the history of FIPS 140 compliance in Go.

For a complete summary of the changes we make, see [the "What's different?" section of the Migration Guide](eng/doc/MigrationGuide.md#whats-different).

We submit changes to the upstream Go project rather than patching it, when
possible. Our goals are to avoid breaking compatibility and to minimize the
number of changes we maintain in this fork.

We call this project a fork even though it isn't a traditional Git fork: the Git branches don't share ancestry with the upstream Git repository.
However, the repository serves the same purpose as a Git fork: to maintain a modified version of the Go source code over time.
The submodule named `go` contains the Go source code, and the `patches` directory contains our changes.
The submodule is updated regularly to the latest commit available in both the upstream repository, <https://go.googlesource.com/go>, and the GitHub mirror, <https://github.com/golang/go>.

## Support

This project follows the upstream Go
[Release Policy](https://go.dev/doc/devel/release#policy).
This means we support each major release (1.X) until there are two newer major
releases. A new Go major version is
[released every six months](https://github.com/golang/go/wiki/Go-Release-Cycle),
so each Go major version is supported for about one year.

When upstream Go releases a new minor version (1.X.Y), we release a
corresponding microsoft/go version that may also include fork-specific changes.
This normally happens once a month.

At any time, we may release a new revision (1.X.Y-Z) to fix an issue without waiting for the next upstream minor release.
Revision releases are uncommon.

Each microsoft/go release is announced at the
[Microsoft for Go Developers](https://devblogs.microsoft.com/go/) blog.
Check out the upstream [golang-announce mailing list](https://groups.google.com/g/golang-announce)
for a summary of the changes in each upstream Go version.

See [SUPPORT.md](SUPPORT.md) for more information about reporting bugs, requesting features, and asking questions.

There are a few additional support resources internal to Microsoft:

* [Languages at Microsoft: Go](https://eng.ms/docs/more/languages-at-microsoft/go/articles/overview).
* [A Microsoft-internal email distribution list 📧 (instant join link)](https://idwebelements.microsoft.com/GroupManagement.aspx?Group=golang-announce&Operation=join)
  for release announcements.

## Download and install

We build the forked Go toolset with the following list of OS/Arch combinations:

* `linux_amd64`
* `linux_armv6l`
* `linux_arm64`
* `windows_amd64`
* `windows_arm64`
* `darwin_amd64`
* `darwin_arm64`

> [!NOTE]
> Cross-compilation to Windows is supported.
> For other OS targets, cgo makes cross-compilation difficult, but it may still be possible.
>
> For example, to build a program for `windows_arm64`, you can cross-compile on a `windows_amd64` or `linux_amd64` host.

Visit the [Migration Guide](eng/doc/MigrationGuide.md) for guidance about how we
recommend migrating existing Go projects to use the Microsoft build of Go. This
guide also helps resolve commonly encountered issues.

The following sections list the ways to get the Microsoft build of Go.

> [!NOTE]
> Don't see an option that works for you? Let us know!  
> File a GitHub issue, or comment on an existing issue in this tag:
  [![](https://img.shields.io/github/labels/microsoft/go/Area-Acquisition)](https://github.com/microsoft/go/labels/Area-Acquisition)

### Docker Container Images

**[microsoft/go-images](https://github.com/microsoft/go-images)** maintains and
documents container images that are available on Microsoft Artifact Registry.

### Azure Linux

The **[Azure Linux](https://github.com/microsoft/azurelinux)** distribution
includes the `golang` package, a build of this fork of Go.

For more information about how to manage the `systemcrypto` migration from 1.24
to 1.25 in Azure Linux 3, see
[the `systemcrypto` section of the Migration Guide](eng/doc/MigrationGuide.md#migration-to-systemcrypto).

### Ubuntu

To install the Microsoft build of Go using an Ubuntu package, first set up the [Linux package repository for Microsoft Products](https://learn.microsoft.com/en-us/linux/packages).
Packages are available in the Ubuntu 22.04 and 24.04 repositories.

After the repository is added, install the Microsoft build of Go by running the following commands:

```bash
sudo apt-get update && sudo apt-get install msft-golang
```

### Binary archive

[Signed builds of Go](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/Downloads.md)
for several platforms are available as `zip` and `tar.gz` files.

### The `go-install.ps1` script

The [cross-platform `go-install.ps1` script](https://github.com/microsoft/go-infra/tree/main/goinstallscript) installs the Microsoft build of Go.
It can install specific versions or the latest releases.

If you use Azure Pipelines, try running the script in a [script step](https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/cmd-line-v2?view=azure-pipelines) and pass the `-AzurePipelinePath` argument to automatically set up `go` in the environment for future steps.

### Build from source

#### Pre-patched source tarball

[The microsoft/go GitHub releases](https://github.com/microsoft/go/releases)
include a source tarball file ending in `.src.tar.gz`. After downloading and
extracting the tar.gz file, build it using the
[upstream instructions](https://go.dev/doc/install/source).

> [!NOTE]
> The `zip` file that GitHub offers for download on the [microsoft/go releases page](https://github.com/microsoft/go/releases) is incomplete: it doesn't include the `go` submodule.
> Make sure to download the `.src.tar.gz` file instead, or [clone the repository using Git and set up the patched submodule](#clone-and-build).

#### Clone and build

First, clone this repository using Git and check out the desired tag or commit.

If you want to contribute to the Microsoft build of Go project, read the [Developer Guide](eng/doc/DeveloperGuide.md).
It lists the steps we recommend to set up a Microsoft build of Go development environment, execute your first build, run the standard library test suite, and contribute a PR.

If you just want to build on your own machine, you may find it more
convenient to use the tools provided by the `eng/run.ps1` script. We use this
script for CI builds. See [eng/README.md](eng/README.md) for more details about
`eng/run.ps1` and other repository infrastructure.

Once built, the Microsoft build of Go binary is found at `go/bin/go`.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

Please read the [Developer Guide](eng/doc/DeveloperGuide.md) for more information about contributing to this project.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

## Data Collection

The software may collect information about you and your use of the software and
send it to Microsoft. Microsoft may use this information to provide services
and improve our products and services. You may turn off the telemetry by
setting the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED` environment variable to `0`.
There are also some features in the software that may enable you and Microsoft
to collect data from users of your applications. If you use these features,
you must comply with applicable law, including providing appropriate notices to
users of your applications together with a copy of Microsoft’s privacy
statement. Our privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704.
You can learn more about data collection and use in the help documentation and
our privacy statement. Your use of the software operates as your consent to
these practices.
