# The Go Programming Language

Go is an open source programming language that makes it easy to build simple,
reliable, and efficient software.

This repository, [microsoft/go](https://github.com/microsoft/go), contains the
infrastructure Microsoft uses to build Go. The submodule named `go` contains the
Go source code. By default, the submodule's remote URL is the official GitHub
mirror of Go, [golang/go](https://github.com/golang/go).

This project is not involved in producing the [official binary distributions
of Go](https://go.dev/dl/).

The canonical Git repository for Go source code is located at
https://go.googlesource.com/go.

Unless otherwise noted, the Go source files are distributed under the
BSD-style license found in the LICENSE file.

## Is this repository a fork?

We believe it is accurate to call this repository a fork. Its branches do not
share Git ancestry with the Go repository, but the repository serves the same
purpose as a Git fork: maintaining a modified version of the Go source code over
time.

This fork exists to produce a version of Go that can be FIPS 140-2 certified
using an OpenSSL backend. Our goal is to share this implementation with others
in the Go community who have the same requirement, and to merge this capability
into upstream Go as soon as possible. See
[eng/doc/fips@dev/official/go1.17-openssl-fips](https://github.com/microsoft/go/tree/dev/official/go1.17-openssl-fips/eng/doc/fips)
for more information about this feature and the history of FIPS 140-2 compliance
in Go.

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
