

We call this project a fork even though it isn't a traditional Git fork: the Git branches don't share ancestry with the upstream Git repository.
However, the repository serves the same purpose as a Git fork: to maintain a modified version of the Go source code over time.
The submodule named `go` contains the Go source code, and the `patches` directory contains our changes.
The submodule is updated regularly to the latest commit available in both the upstream repository, <https://go.googlesource.com/go>, and the GitHub mirror, <https://github.com/golang/go>.
* `linux_amd64`
* `linux_armv6l`
* `linux_arm64`
* `windows_amd64`
* `darwin_amd64`
* `darwin_arm64`

For detailed platform support information across different Go versions, see [SUPPORTED_PLATFORMS.md](SUPPORTED_PLATFORMS.md).

## Support

See [SUPPORT.md](SUPPORT.md) for more information about reporting bugs, requesting features, and asking questions.

There are a few additional support resources internal to Microsoft:

* [(Microsoft-internal) Languages at Microsoft: Introduction to Go](https://eng.ms/docs/more/languages-at-microsoft/go/articles/overview).
* [(Microsoft-internal) Languages at Microsoft: Get Help with Go](https://eng.ms/docs/more/languages-at-microsoft/go/articles/support).
  * Includes internal Microsoft support channels such as an email contact for our team and a community Teams group.

## Release cycle and policy

This project follows the upstream Go [Release Policy](https://go.dev/doc/devel/release#policy).
This means we support each major release (1.X) until there are two newer major releases.
A new Go major version is [released every six months](https://github.com/golang/go/wiki/Go-Release-Cycle), so each Go major version is supported for about one year.

When upstream Go releases a new minor version (1.X.Y), we release a corresponding microsoft/go version that may also include fork-specific changes.
This normally happens once a month.

At any time, we may release a new revision (1.X.Y-Z) to fix an issue without waiting for the next upstream minor release.
Revision releases are uncommon.

We announce each Microsoft build of Go release through the following channels:

* [Microsoft for Go Developers blog](https://devblogs.microsoft.com/go/).
* [Microsoft-internal email distribution list 📧 (instant join link)](https://idwebelements.microsoft.com/GroupManagement.aspx?Group=golang-announce&Operation=join).

The Go team announces upstream releases on the [golang-announce mailing list](https://groups.google.com/g/golang-announce).
These announcement emails include a carefully written summary of the changes that may not be found elsewhere.

## Download and install

We build the Microsoft build of Go toolset with the following OS/Arch combinations:

| OS | `amd64` | `arm64` | `armv6l` |
| --- | :---: | :---: | :---: |
| `linux` | ✓ | ✓ | ✓ |
| `windows` | ✓ | ✓ | |
| `darwin` (macOS) | ✓ | ✓ | |

Visit the [Migration Guide](eng/doc/MigrationGuide.md) for guidance about how we recommend migrating existing Go projects to use the Microsoft build of Go.
This guide also helps resolve commonly encountered issues.

The [Installation](eng/doc/Installation.md) documentation contains sections describing each of the following installation methods:

* [Docker Container Images](eng/doc/Installation.md#docker-container-images)
* [Azure Linux](eng/doc/Installation.md#azure-linux)
* [Ubuntu](eng/doc/Installation.md#ubuntu)
* [Azure Pipelines `GoTool@0` task](eng/doc/Installation.md#azure-pipelines-gotool0-task)
* [GitHub Actions `setup-go` action](eng/doc/Installation.md#github-actions-setup-go-action)
* [The `go-install.ps1` script](eng/doc/Installation.md#the-go-installps1-script)
* [Binary archive](eng/doc/Installation.md#binary-archive) (`tar.gz` and `zip`)
* [Build from source](eng/doc/Installation.md#build-from-source)

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
