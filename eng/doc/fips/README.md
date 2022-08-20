This directory contains documentation about FIPS and the FIPS implementation in the Microsoft fork of Go.

* README.md (this file): a general overview and first steps.
* [**FIPS 140-2 User Guide** (UserGuide.md)](UserGuide.md): notes on FIPS compliance of specific crypto APIs.

# Crypto FIPS 140-2 support

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

The Go `crypto` package is not FIPS certified, and the Go team has stated that it won't be, e.g. in [golang/go/issues/21734](https://github.com/golang/go/issues/21734#issuecomment-326980213) Adam Langley says:

> The status of FIPS 140 for Go itself remains "no plans, basically zero chance".

On the other hand, Google maintains the [goexperiment](https://pkg.go.dev/internal/goexperiment) `boringcrypto`, that uses cgo and BoringSSL to implement various crypto primitives. As BoringSSL is FIPS 140-2 certified, an application built using this flag is more likely to be FIPS 140-2 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140-2 standard.

In addition to that, the boringcrypto flag also provides a mechanism to restrict all TLS configuration to FIPS-approved settings. The effect is triggered by importing the fipsonly package anywhere in a program, as in:

```go
  import _ "crypto/tls/fipsonly"
```

Prior to Go 1.19, the boringcrypto changes were maintained in the `dev.boringcrypto*` branches of Go: https://github.com/golang/go/blob/dev.boringcrypto/README.boringcrypto.md. For more details about the merge, see [golang/go#51940](https://github.com/golang/go/issues/51940).

## Microsoft Go fork FIPS compliance

The Microsoft Go fork modifies the Go runtime to implement several crypto primitives using cgo to call into a platform-provided cryptographic library rather than use the standard Go crypto implementations. This allows Go programs to use a platform-provided FIPS 140-2 certified crypto library.

On Linux, the fork uses [OpenSSL](https://www.openssl.org/) through the [go-crypto-openssl](https://github.com/microsoft/go-crypto-openssl) module. On Windows, [CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/about-cng), using [go-crypto-winnative](https://github.com/microsoft/go-crypto-winnative). Similar to BoringSSL, certain OpenSSL and CNG versions are FIPS 140-2 certified.

It is important to note that an application built with Microsoft's Go toolchain and running in FIPS compatible mode is not FIPS compliant _per-se_. It is on the application development team to use FIPS-compliant crypto primitives and workflows. The crypto runtime will fall back to Go standard library crypto in case it cannot provide a FIPS-compliant implementation, e.g. when hashing a message using `crypto/md5` hashes or when using an AES-GCM cipher with a non-standard nonce size.

## Usage: Build

### Go 1.18

In Go 1.18 and earlier, the Microsoft Go FIPS-compatible builds are maintained in the `microsoft/dev.boringcrypto*` branches. Only a Linux implementation using OpenSSL is supported for these versions.

1. Get a `1.18-fips` build of the Microsoft Go toolset. See [the microsoft/go readme](https://github.com/microsoft/go#binary-distribution) for options.
1. Build your Go program using this Go toolset.
1. The built program now includes the ability to use OpenSSL crypto and FIPS compatibility mode at runtime.

The whole OpenSSL functionality can be disabled even while using a `1.18-fips` Go toolset by building your program with `-tags gocrypt`.

### Go 1.19+

In Go 1.19 onward, the FIPS-related changes are maintained in the `microsoft/release-branch.go*` branches in this repository.

1. Get the standard Microsoft build of Go. There is no separate `-fips` build. See [the microsoft/go readme](https://github.com/microsoft/go#binary-distribution) for options.
1. Enable the desired GOEXPERIMENT and build your program.
    * To build for Linux/OpenSSL, for example:
      ```sh
      GOEXPERIMENT=opensslcrypto go build ./myapp
      ```
    * To build for Windows/CNG in PowerShell, for example:
      ```pwsh
      $env:GOEXPERIMENT = "cngcrypto"
      go build ./myapp
      ```
1. The built program will use the specified platform-provided cryptographic library whenever it calls a Go standard library crypto API, and FIPS compatibility can be enabled at runtime.

## Usage: Runtime

A program built with Go 1.19+ and `opensslcrypto` always uses the OpenSSL library present on the system for crypto APIs. Likewise for `cngcrypto` and CNG. If the platform's crypto library can't be found or loaded, the Go program panics during initialization.

In Go 1.18 and earlier, the program uses OpenSSL only if the program is running in FIPS mode.

The following sections describe how to enable FIPS mode.

### Linux FIPS mode (OpenSSL)

To set FIPS mode on Linux, use one of the following options. The first match wins:

- Explicitly enable it by setting the environment variable `GOFIPS=1`.
- Explicitly disable it by setting the environment variable `GOFIPS=0`.
- Implicitly enable it by booting the Linux Kernel in FIPS mode.
  - Linux FIPS mode sets the content of `/proc/sys/crypto/fips_enabled` to `1`. The Go runtime reads this file.

If the Go runtime detects a FIPS preference, it configures OpenSSL during program initialization. This includes disabling FIPS mode if `GOFIPS=0`. If configuration fails, program initialization panics.

If no option is detected, the Go runtime doesn't set the OpenSSL FIPS mode, and the standard OpenSSL configuration is left unchanged. For more information about the standard OpenSSL FIPS behavior, see https://www.openssl.org/docs/fips.html.

### Windows FIPS mode (CNG)

To enable FIPS mode on Windows, [enable the Windows FIPS policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#step-3-enable-the-fips-security-policy). For testing purposes, this can be set via the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`, dword value `Enabled` set to `1`.

To make the Go runtime panic during program initialization if FIPS mode is not enabled, set the environment variable `GOFIPS=1`.

> Unlike `opensslcrypto`, a Windows program built with `cngcrypto` doesn't include the ability to enable/disable FIPS, only ensure it's enabled. Windows FIPS mode is not a per-process setting, and changing it may require elevated permissions. Adding this feature would likely have unintended consequences.

## Features

### No code changes required

Applications requiring FIPS-compliance don't require any code change to activate FIPS compatibility mode. The Go runtime will favor OpenSSL/CNG crypto primitives over Go standard library when the application is FIPS-enabled.

Code changes may be necessary to conform to FIPS requirements, but only ones that would be necessary regardless of how the FIPS-compatible API were implemented. Examples would be removing algorithms and key sizes forbidden by FIPS 140-2. For more information, see the [FIPS User Guide](UserGuide.md).

### Multiple OpenSSL versions allowed

OpenSSL does not maintain ABI compatibility between different releases, even if only the patch version is increased. The Go crypto package has support for multiple OpenSSL versions, yet each version has a different amount of automated validation:

- OpenSSL 1.1.1: the Microsoft CI builds official releases and runs automated tests with this version.
- OpenSSL 1.0.1: the Microsoft CI builds official releases, but doesn't run tests, so it may not produce working applications.
- OpenSSL 1.1.0 and 3.0: the Microsoft CI does not build nor test these versions, so they may or may not work.

Versions not listed above are not supported at all.

### Dynamic OpenSSL linking

Go automatically loads the OpenSSL shared library `libcrypto` using [dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html) when initializing. Therefore, dlopen's shared library search conventions also apply here.

The `libcrypto` shared library file name varies among different platforms, so a best-effort is done to find and load the right file:

- The base name is always `libcrypto.so.`
- Well-known version strings are appended to the base name, until the file is found, in the following order: `3` -> `1.1` -> `11` -> `111` -> `1.0.2` -> `1.0.0`.

This algorithm can be overridden by setting the environment variable `GO_OPENSSL_VERSION_OVERRIDE` to the desired version string. For example, `GO_OPENSSL_VERSION_OVERRIDE="1.1.1k-fips"` makes the runtime look for the shared library `libcrypto.so.1.1.1k-fips` before running the checks for well-known versions.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version used when building a program does not have to match with the OpenSSL version used when running it. It is even possible to build a program using plain Go crypto (i.e. setting `GOFIPS=0`) and then running that same program in FIPS mode.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain.

### TLS with FIPS-approved settings

The Go TLS stack will automatically use OpenSSL crypto primitives when running in FIPS mode. Yet, the FIPS 140-2 standard places additional restrictions on TLS communications, mainly on which cyphers and signers are allowed.

A program can import the `crypto/tls/fipsonly` package to configure the Go TLS stack so it is compliant with these restrictions. The configuration is done by an `init()` function. Note that this can reduce compatibility with old devices that do not support modern cryptography techniques such as TLS 1.2.

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- All crypto stubs are a mirror of Google's [dev.boringcrypto branch](https://github.com/golang/go/tree/dev.boringcrypto) and the release branch ports of that branch.
- The mapping between BoringSSL and OpenSSL APIs is taken from Fedora's [Go fork](https://pagure.io/go).
- Portable OpenSSL implementation ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Disclaimer

A program running in FIPS mode can claim it is using a FIPS-certified cryptographic module, but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.
