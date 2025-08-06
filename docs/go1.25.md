# Microsoft build of Go 1.25 release notes

After the release of 1.25, 1.23 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## System-provided cryptography enabled by default

The Microsoft build of Go 1.25 enables the `systemcrypto` experiment by default:

- **Linux:** Uses OpenSSL (requires cgo)
- **Windows:** Uses CNG (does *not* require cgo)

> [!NOTE]
> **macOS:** system-provided crypto backend remains in preview and is not enabled by default.

This aligns with Microsoft's internal security and compliance policies. You may need to take action if your builds rely on Linux without cgo, use distroless containers, or have cross-distro deployment requirements.

To opt out of systemcrypto, set the `GOEXPERIMENT` environment variable to include `nosystemcrypto`.

For full documentation, see the [Microsoft build of Go FIPS guide](https://github.com/microsoft/go/blob/microsoft/release-branch.go1.25/eng/doc/fips/UserGuide.md).

## Telemetry collection enabled

The Microsoft build of Go 1.25 introduces opt-out telemetry collection to help us prioritize features, identify performance bottlenecks, and understand real-world developer workflows. All telemetry is anonymized and handled in accordance with [Microsoft's privacy policies](https://privacy.microsoft.com/privacystatement).

To disable telemetry, set the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED` environment variable to be `0`.
