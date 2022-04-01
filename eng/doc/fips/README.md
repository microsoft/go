# Crypto FIPS 140-2 support

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

The Go `crypto` package is not FIPS certified, and the Go team has stated that it won't be, e.g. in [golang/go/issues/21734](https://github.com/golang/go/issues/21734#issuecomment-326980213) Adam Langley says:

> The status of FIPS 140 for Go itself remains "no plans, basically zero chance".

On the other hand, Google maintains a branch that uses cgo and BoringSSL to implement various crypto primitives: https://github.com/golang/go/blob/dev.boringcrypto/README.boringcrypto.md. As BoringSSL is FIPS 140-2 certified, an application using that branch is more likely to be FIPS 140-2 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140-2 standard.

In addition to that, the dev.boringcrypto branch also provides a mechanism to restrict all TLS configuration to FIPS-approved settings. The effect is triggered by importing the package anywhere in a program, as in:

```go
  import _ "crypto/tls/fipsonly"
```

## Microsoft Go fork FIPS compliance

Microsoft's Go Linux runtime has been modified to implement several crypto primitives using cgo and OpenSSL. Similar to BoringSSL, certain OpenSSL versions are also FIPS 140-2 certified.

These changes are maintained in the `microsoft/dev.boringcrypto*` branches in this repository.

It is important to note that an application built with Microsoft's Go toolchain and running in FIPS compatible mode is not FIPS compliant _per-se_. It is on the application development team to use FIPS-compliant crypto primitives and workflows. The crypto runtime will fall back to Go standard library crypto in case it cannot provide a FIPS-compliant implementation, e.g. when hashing a message using `crypto/md5` hashes or when using an AES-GCM cipher with a non-standard nonce size.

## Usage

FIPS compatibility mode, and therefore the OpenSSL crypto backend, can be enabled using any of these options:

- Explicitly setting the environment variable `GOFIPS=1`.
- Implicitly enabling it by booting the Linux Kernel in FIPS mode.
  - Linux FIPS mode sets the content of `/proc/sys/crypto/fips_enabled` to `1`. The Go runtime reads this file.
  - To opt out, set `GOFIPS=0`.

Whichever is the approach used, the program initialization will panic if FIPS mode is requested but the Go runtime can't find a suitable OpenSSL shared library or OPENSSL FIPS mode can't be enabled.

The whole OpenSSL functionality can be disabled by building your program with `-tags gocrypto`.

## Features

### No code changes required

Applications requiring FIPS-compliance don't require any code change to activate FIPS compatibility mode. The Go runtime will favor OpenSSL crypto primitives over Go standard library when the application is FIPS-enabled.

### Multiple OpenSSL versions allowed

OpenSSL does not maintain ABI compatibility between different releases, even if only the patch version is increased. The Go crypto package has support for multiple OpenSSL versions, yet each version has a different amount of automated validation:

- OpenSSL 1.1.1: the Microsoft CI builds official releases and runs automated tests with this version.
- OpenSSL 1.0.1: the Microsoft CI builds official releases, but doesn't run tests, so it may not produce working applications.
- OpenSSL 1.1.0 and 3.0: the Microsoft CI does not build nor test these versions, so they may or may not work.

Versions not listed above are not supported at all.

### Dynamic OpenSSL linking

Go automatically loads the OpenSSL shared library `libcrypto` using [dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html) when initializing a FIPS-enabled program. Therefore, dlopen's shared library search conventions also apply here.

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
