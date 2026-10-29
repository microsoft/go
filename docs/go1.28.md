# Microsoft build of Go 1.28 release notes

After the release of 1.28, 1.26 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Toolchain

To align with Microsoft's security policies, Linux builds now default to
position-independent executables (`-buildmode=pie`) on amd64, arm64, loong64,
ppc64, ppc64le, and s390x. Windows and macOS (`darwin`) builds already used
PIE by default.

Other Linux architectures and `-race` builds retain their previous defaults.
Use `-buildmode=exe` to opt out. Programs without direct or indirect
dependencies on Go's `crypto` packages now also require a dynamic loader at
runtime. See the [PIE documentation](../eng/doc/AdditionalFeatures.md#position-independent-executables-on-linux)
for details and guidance on fully static builds.

## Cryptography

The `crypto/boring` package is no longer enabled by system crypto.
It retains its upstream BoringCrypto-specific build constraint.

Setting `MS_GOTLSMLKEM=0` when building a program now changes its `tlsmlkem`
GODEBUG default to `0`, disabling the default use of ML-KEM hybrid TLS groups,
including X25519MLKEM768. Setting `GODEBUG=tlsmlkem=1` at runtime re-enables
these groups, subject to the other TLS settings. See the
[TLS settings documentation](../eng/doc/AdditionalFeatures.md#tls-setting-alignment-with-microsoft-internal-policies)
for details.
