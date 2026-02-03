# Microsoft build of Go 1.26 release notes

After the release of 1.26, 1.24 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Toolchain

The `GOCACHE` environment variable now defaults to `os.UserCacheDir()/ms-go-build` instead of `os.UserCacheDir()/go-build`.

The [buildinfo](https://pkg.go.dev/debug/buildinfo) embedded at build time now includes Microsoft-specific version information in a new `microsoft_toolset_version` setting.
A new GODEBUG setting `ms_version=1` changes [`runtime.Version()`](https://pkg.go.dev/runtime#Version) to return the Microsoft-specific version string.
A new [linker flag](https://pkg.go.dev/cmd/link) `-ms_upstreamversion=0` uses the Microsoft-specific version as the main Go version embedded in the output instead of the upstream version.
For more information, see [the Additional Features document](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/AdditionalFeatures.md#version-string-changes-to-identify-the-microsoft-build-of-go).

## Systemcrypto

### Configuration

You can disable `systemcrypto` at build time by setting the environment variable `MS_GO_NOSYSTEMCRYPTO` to `1`.
This is now the preferred method for disabling systemcrypto when necessary.

### Backends

#### Windows

Setting the FIPS preference to enabled will no longer cause a panic when the Windows FIPS policy is disabled.

#### OpenSSL

Improved support for the Fedora OpenSSL FIPS provider.

Binaries can now be built without using cgo by setting `GOEXPERIMENT=ms_nocgo_opensslcrypto`.

#### Darwin

The backend is no longer in preview and is now fully supported.
It is enabled by default on macOS.

Binaries are now built without using cgo.

### Supported Algorithms

The following hash functions are now implemented using the systemcrypto backends:

- SHA-3-224
- SHA-3-256
- SHA-3-384
- SHA-3-512
- SHAKE-128
- SHAKE-256

The following ECDH curves are now implemented using the systemcrypto backends:

- X25519

The following ML-KEM sizes are now implemented using the systemcrypto backends:

- 768
- 1024

The following TLS groups are now implemented using the systemcrypto backends:

- X25519
- X25519MLKEM768
- SecP256r1MLKEM768
- SecP384r1MLKEM1024

The following TLS cipher suites are now implemented using the systemcrypto backends:

- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

## TLS Settings

The TLS curves X25519 and X25519MLKEM768 can be disabled using the GODEBUG setting `ms_tlsx25519=0`.

The TLS default settings are now aligned with Microsoft TLS internal policies.
This behavior can be disabled using the GODEBUG setting `ms_tlsprofile=off`.
The changes from standard Go TLS default settings are:

- TLS cipher suites using AES-256 are now preferred over those using AES-128.
- TLS cipher suites using CHACHA20_POLY1305 are no longer preferred over AES-GCM cipher suites when the client or server supports hardware acceleration for AES.
- TLS groups supported by the systemcrypto backends are now preferred over those that are not.
