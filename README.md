# The Go Programming Language

Go is an open source programming language that makes it easy to build simple,
reliable, and efficient software.

This repository, [microsoft/go](https://github.com/microsoft/go), contains the
infrastructure Microsoft uses to build Go. The submodule named `go` contains the
Go source code. By default, the submodule's remote URL is the official GitHub
mirror of Go, [golang/go](https://github.com/golang/go).  The canonical Git
repository for Go source code is located at https://go.googlesource.com/go.

This project is not involved in producing the [official binary distributions
of Go](https://go.dev/dl/).

Unless otherwise noted, the Go source files are distributed under the
BSD-style license found in the LICENSE file.

## Why does this fork exist?

The `microsoft/dev.boringcrypto*` branches produce a modified version of Go that
can be used to build FIPS 140-2 compliant applications. Our goal is to share
this implementation with others in the Go community who have the same
requirement, and to merge this capability into upstream Go as soon as possible.
See [eng/doc/fips](eng/doc/fips) for more information about this feature and the
history of FIPS 140-2 compliance in Go.

The `microsoft/release-branch.go*` branches rebuild released versions of Go with
no significant changes, for use within Microsoft.

We call this repository a fork even though it isn't a traditional Git fork. Its
branches do not share Git ancestry with the Go repository. However, the
repository serves the same purpose as a Git fork: maintaining a modified version
of the Go source code over time.

## Download and install

This repository's infrastructure currently supports these OS/Arch combinations:

* `linux_amd64`
* `windows_amd64`

See [eng/README.md](eng/README.md) for more details about the infrastructure.

### Build from source

Prerequisites:

* [PowerShell 6+](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
* [Go install from source prerequisites](https://go.dev/doc/install/source)
  * Exception: this repository's build script automatically downloads a
    bootstrap version of Go.

After cloning the repository, use the following build command. You can pass the
`-help` flag to show more options:

```
pwsh eng/run.ps1 build -refresh
```

The resulting Go binary is at `go/bin/go`.

> If you download a source archive from a GitHub release, use the official Go
> install from source instructions. These source archives only include the `go`
> directory, not the microsoft/go build infrastructure.

### Binary distribution

* **[microsoft/go-images](https://github.com/microsoft/go-images)** distributes
  the binaries of this Go fork by producing Docker images that are published to
  the Microsoft Container Registry. This is the recommended way to use the
  Microsoft build of Go.

* [**Binary archives**: visit the `microsoft/main` branch `eng/doc/Downloads.md`
  file](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/Downloads.md)
  to download binaries and source tarballs built by supported release branches.

* [**GitHub Releases**: the microsoft/go GitHub
  releases](https://github.com/microsoft/go/releases) have source code archive
  attachments.

More options are planned in the future. See the issue tag:
[![](https://img.shields.io/github/labels/microsoft/go/Area-Release)](https://github.com/microsoft/go/labels/Area-Release)

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

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
