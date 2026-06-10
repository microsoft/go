# Supported Platforms

This document describes the platforms supported by the Microsoft build of Go.

"Support" means that Microsoft will accept bug reports for these platforms and
investigate issues. Platforms outside this scope are provided support on a
best-effort basis with no guarantees.

For information about which platforms have prebuilt toolset binaries available,
see [Downloads.md](Downloads.md).

## Platform Support Matrix

| OS/Arch | Minimum Versions | Crypto Backend | Notes |
|---------|-----------------|----------------|-------|
| linux/amd64 | Azure Linux 3.0+, Ubuntu 22.04+ | OpenSSL | |
| linux/arm64 | Azure Linux 3.0+, Ubuntu 22.04+ | OpenSSL | |
| linux/arm32 | Ubuntu 22.04+ | OpenSSL | |
| windows/amd64 | Windows 10+, Windows Server 2016+ | CNG | |
| windows/arm64 | Windows 11+, Windows Server 2025+ | CNG | |
| darwin/amd64 | macOS 13+ | CryptoKit/CommonCrypto | Added in Go 1.24 |
| darwin/arm64 | macOS 13+ | CryptoKit/CommonCrypto | Added in Go 1.24 |

## OpenSSL Versions

The following OpenSSL versions are supported on Linux platforms:

- OpenSSL 1.1.0 and 1.1.1
- OpenSSL 3.x (built-in providers, or SymCrypt provider v1.6.1+)

## Getting Help

If you need support for an additional platform or encounter issues with a supported platform:

1. Check existing issues with the [Area-Acquisition](https://github.com/microsoft/go/labels/Area-Acquisition) label
1. [File a new issue](https://github.com/microsoft/go/issues/new/choose) if your platform or issue isn't already covered
