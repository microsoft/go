# Microsoft build of Go 1.27 release notes

After the release of 1.27, 1.25 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Systemcrypto

See the [FIPS documentation Go 1.27 changelog](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md#go-127-aug-2026) for more information.

### Configuration

`systemcrypto` is no longer a `GOEXPERIMENT` setting.
It is enabled automatically on supported platforms and no longer appears in `go env GOEXPERIMENT`, `goexperiment.Flags`, or other GOEXPERIMENT-derived output.
`GOEXPERIMENT=systemcrypto` and `GOEXPERIMENT=nosystemcrypto` have been removed and are now rejected with an error.
To disable `systemcrypto`, set the environment variable `MS_GO_NOSYSTEMCRYPTO` to `1`.
The `goexperiment.systemcrypto` build tag is still emitted when `systemcrypto` is enabled, and its behavior has not changed.

The per-platform GOEXPERIMENTs `opensslcrypto`, `cngcrypto`, and `darwincrypto` have been removed.
Using any of them results in a build error.
The build tags associated with the removed GOEXPERIMENTs remain supported for legacy source compatibility.

### FIPS 140

`GODEBUG=fips140=only` has been added.
It acts as `fips140=on`, but also panics if a non-FIPS-approved algorithm is used.

`GODEBUG=fips140=off` now explicitly disables FIPS mode and skips the platform-specific FIPS detection (such as the Linux kernel FIPS flag at `/proc/sys/crypto/fips_enabled`).

The `GOFIPS` environment variable check now matches its intended behavior: only `GOFIPS=1` enables FIPS mode, and any other value (including `0` and the empty string) is treated as if `GOFIPS` were unset.
The same applies to `GOLANG_FIPS`.

### Backends

#### OpenSSL

On Linux, `systemcrypto` now supports `CGO_ENABLED=0` on supported cgo-less OpenSSL architectures by default.
The Go 1.26 `GOEXPERIMENT=ms_nocgo_opensslcrypto` experiment has been removed because this behavior is now part of the default `systemcrypto` backend selection.

#### FreeBSD

`systemcrypto` is now supported on FreeBSD (`amd64` and `arm64`), using the same OpenSSL backend as on Linux.

### Supported Algorithms

The following ML-DSA parameter sets are now implemented using the systemcrypto backends:

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
