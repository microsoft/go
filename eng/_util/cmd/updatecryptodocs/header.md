# Cross-Platform Cryptography in the Microsoft build of Go

Cryptographic operations in the Microsoft build of Go are delegated to the operating system (OS) libraries in some conditions.
The high level conditions and the benefits of delegating cryptographic operations are described in the [Microsoft build of Go FIPS README](./fips/README.md).
At a fine-grained level, Go apps will fall back to the native Go implementation of an algorithm if the OS libraries don't support it.
This article identifies the features that are supported on each platform.

This article assumes you have a working familiarity with cryptography in Go.

## Platform support

The Microsoft build of Go supports the following platforms:

### Windows

On Windows, the Microsoft build of Go uses the [CNG library (Cryptography API: Next Generation)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) for cryptographic operations.
CNG is available since Windows Vista and Windows Server 2008 and it doesn't require any additional installation nor configuration.

### Linux

On Linux, the Microsoft build of Go uses the [OpenSSL crypto library](https://docs.openssl.org/3.0/man7/crypto/) for cryptographic operations.
OpenSSL is normally available on Linux distributions, but it may not be installed by default.
If it is not installed, you can install it using the package manager of your distribution.

OpenSSL 3 implements all the cryptographic algorithms using [Providers](https://docs.openssl.org/3.0/man7/crypto/#providers).
The Microsoft build of Go officially supports the built-in providers and [SCOSSL (SymCrypt provider for OpenSSL)](https://github.com/microsoft/SymCrypt-OpenSSL) v1.6.1 or later.
SCOSSL is expected to be used with the default built-in provider enabled as a fallback (which is the case when using [Azure Linux 3](https://github.com/microsoft/AzureLinux)).

### FreeBSD

Since Go 1.27, the Microsoft build of Go uses the [OpenSSL crypto library](https://docs.openssl.org/3.0/man7/crypto/) on FreeBSD, the same backend as on Linux.
The algorithm support listed in the Linux column of the tables below also applies to FreeBSD.

### macOS

On macOS, the Microsoft build of Go uses [CommonCrypto](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/Common%20Crypto.3cc.html) and [CryptoKit](https://developer.apple.com/documentation/cryptokit) for cryptographic operations.
CommonCrypto and CryptoKit are shipped with macOS and don't require any additional installation nor configuration.
Currently macOS 13 and above is supported.

## Cgo

Sometimes, cgo is not available:

* When performing a cross-platform build, a suitable C compiler for cgo is often not available or very difficult to set up correctly.
* Cgo may be intentionally disabled to simplify the build process, or for security or performance reasons.
* Cgo may be intentionally disabled to avoid producing a binary that depends on the build system's glibc version. The dependency may be too new, causing the program to fail to run on some target systems. See ["glibc resolution failure on Linux" in the Migration Guide](MigrationGuide.md#glibc-resolution-failure-on-linux).

The Microsoft build of Go attempts to use a cgo-less `systemcrypto` backend when cgo is not enabled, but on some uncommon OS and architecture combinations, this is not supported:

| Target platform | Cgo enabled | Cgo disabled |
| --- | --- | --- |
| Linux | ✔️ | ⚠️<sup>1</sup>  |
| FreeBSD (since Go 1.27) | ✔️ | ⚠️<sup>2</sup> |
| Windows | ✔️ | ✔️ |
| macOS | ✔️ | ✔️ |

<sup>1</sup> Supported on **amd64**, **arm64**, and [many other architectures](NocgoOpenSSL.md#supported-architectures).

<sup>2</sup> Supported on **amd64** and **arm64** architectures.

> [!IMPORTANT]
> When using Go 1.26 and targeting Linux or FreeBSD, the table only applies if `GOEXPERIMENT=ms_nocgo_opensslcrypto` is set.
> Otherwise, cgo is always required.
> See [No-cgo OpenSSL Backend](NocgoOpenSSL.md) for details.

## Table legend

The following legend describes the symbols used in the tables to indicate the level of support for each cryptographic algorithm:

| Symbol | Meaning                                                                                                                      |
| ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| ✔️     | Supported, possibly with minor limitations that don't require special configuration when using the latest Go and OS versions |
| ⚠️     | Supported with limitations that require special configuration action                                                         |
| ❌     | Not supported                                                                                                                |

When an algorithm is not supported or the limitations are exceeded, the Microsoft build of Go will fall back to the Go implementation.
