# Microsoft build of Go 1.27 release notes

After the release of 1.27, 1.25 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Systemcrypto

See the [Go 1.27 changelog in the FIPS documentation](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md#go-127-aug-2026) for more information.

### Systemcrypto is no longer a GOEXPERIMENT setting

`systemcrypto` is still enabled by default on supported platforms, as it has been since Go 1.25 (Linux and Windows) and Go 1.26 (macOS).
What's new in 1.27 is that it is now selected automatically by the toolchain instead of being configured through `GOEXPERIMENT`:

- Setting the environment variable `GOEXPERIMENT` to `systemcrypto` or `nosystemcrypto` is now rejected with an error.
  To disable `systemcrypto`, set the environment variable `MS_GO_NOSYSTEMCRYPTO` to `1` instead.
- `systemcrypto` no longer appears in `go env GOEXPERIMENT`, `goexperiment.Flags`, or other GOEXPERIMENT-derived output.

The per-platform GOEXPERIMENTs `opensslcrypto`, `cngcrypto`, and `darwincrypto` have also been removed and now cause a build error.

The `goexperiment.systemcrypto` build tag is still emitted when `systemcrypto` is enabled.
That tag, and the build tags for the removed per-platform experiments, remain supported for source compatibility, with no change in behavior.

### New platform and backend support

`systemcrypto` is now supported on FreeBSD (`amd64` and `arm64`), using the same OpenSSL backend as on Linux.

On Linux, `systemcrypto` now supports `CGO_ENABLED=0` on architectures that have a cgo-less OpenSSL implementation.
This replaces the Go 1.26 `GOEXPERIMENT=ms_nocgo_opensslcrypto` experiment, which has been removed.

### New algorithms

The `systemcrypto` backends now implement the following ML-DSA parameter sets:

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

### FIPS 140

`GODEBUG=fips140=only` has been added.
It acts like `fips140=on`, but also panics if a non-FIPS-approved algorithm is used.

`GODEBUG=fips140=off` now explicitly disables FIPS mode and skips the platform-specific FIPS detection (such as the Linux kernel FIPS flag at `/proc/sys/crypto/fips_enabled`).

The `GOFIPS` and `GOLANG_FIPS` environment variable checks now match their intended behavior: only the value `1` enables FIPS mode, and any other value (including `0` and the empty string) is treated as if the variable were unset.
