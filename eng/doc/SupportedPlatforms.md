# Supported Platforms

This document describes the platforms supported by the Microsoft build of Go.

"Support" means that Microsoft will accept bug reports for these platforms and investigate issues.
Platforms outside this scope are supported on a best-effort basis with no guarantees.

> [!NOTE]
> This document describes the platforms that a program built by the Microsoft build of Go can run on.
> We don't necessarily provide a toolset for every platform we support.
> See the [Downloads](./Downloads.md) table for the list of prebuilt Go toolsets we provide, and [Installation](./Installation.md) for the list of ways we recommend installing them.

## Platform Support Matrix

| Go OS/Arch | Minimum Versions |
|---|---|
| darwin/amd64 | macOS 13 |
| darwin/arm64 | macOS 13 |
| linux/amd64 | Azure Linux 3.0, Ubuntu 22.04 |
| linux/arm64 | Azure Linux 3.0, Ubuntu 22.04 |
| linux/arm | Ubuntu 22.04 |
| windows/amd64 | Windows 10, Windows Server 2016 |
| windows/arm64 | Windows 11, Windows Server 2025 |

## OpenSSL Versions

The following OpenSSL versions are supported on Linux platforms:

- OpenSSL 1.1.1
- OpenSSL 3.x (built-in providers, or SymCrypt provider v1.6.1+)

## Getting Help

If the Microsoft build of Go doesn't support a platform you need, please let us know.
Look for an existing issue with the [![Area-Acquisition](https://img.shields.io/github/labels/microsoft/go/Area-Acquisition)](https://github.com/microsoft/go/labels/Area-Acquisition) label and leave a comment.
Otherwise, [file a new issue](https://github.com/microsoft/go/issues/new/choose).

You can also get in contact using our other [support resources](/README.md#support).
