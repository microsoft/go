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

## The microsoft/release-branch.go1.4 branch

This branch isn't directly used to build Go. It is a place to put a 1.4 Git tag,
which lets us create a GitHub release that serves a mirror of the official 1.4
Go C bootstrap source archive. The mirrored source code can then be used by
other teams in Microsoft to build Go from source.

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
