# Microsoft build of Go 1.28 release notes

After the release of 1.28, 1.26 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Cryptography

The `crypto/boring` package is no longer enabled by system crypto.
It retains its upstream BoringCrypto-specific build constraint.
