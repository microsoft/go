# Microsoft Build of Go - Additional Features

This document provides a comprehensive overview of all Microsoft-specific features currently supported in the Microsoft build of Go.

## Crypto Backend Features

These features enable system-provided cryptographic libraries for FIPS 140 compliance and improved security.

### `GOEXPERIMENT=systemcrypto`
- **Purpose**: Automatically selects the recommended crypto backend for the target platform
- **Behavior**: 
  - Linux: Enables `opensslcrypto` (OpenSSL)
  - Windows: Enables `cngcrypto` (CNG - Cryptography Next Generation)
  - macOS: Enables `darwincrypto` (CommonCrypto & CryptoKit) (Go 1.24+)
- **Default**: Enabled by default on Linux and Windows since Go 1.25
- **Notes**: Acts as an alias that also satisfies individual backend build constraints, set `MS_GO_NOSYSTEMCRYPTO: 1` if backend opt-out needed

## TLS Features

### `GOEXPERIMENT=ms_tls_config_schannel`
- **Purpose**: Filters and orders cipher suites according to Windows Schannel settings
- **Platform**: Windows only (no effect on Windows Server 2012/Windows 8 and earlier)
- **Available Since**: Go 1.24.7
- **Use Case**: Ensures TLS configuration matches system security policies
- **Notes**: This feature may reduce compatibility between TLS clients or servers and other implementations. Enable it only if your use case specifically requires alignment with Windows Schannel configuration settings.

## Deprecated Features

These features are deprecated and may be removed in future releases.

### `GOEXPERIMENT=opensslcrypto`
- **Purpose**: Uses OpenSSL for cryptographic operations on Linux
- **Platform**: Linux only
- **Requirements**: CGO must be enabled
- **Status**: Deprecated in 1.25
- **Replacement**: Enabled by default (via `systemcrypto`), set `MS_GO_NOSYSTEMCRYPTO: 1` if backend opt-out needed

### `GOEXPERIMENT=cngcrypto`
- **Purpose**: Uses Windows CNG (Cryptography Next Generation) API
- **Platform**: Windows (amd64 and arm64) only
- **Status**: Deprecated in 1.25
- **Replacement**: Enabled by default (via `systemcrypto`), set `MS_GO_NOSYSTEMCRYPTO: 1` if backend opt-out needed

### `GOEXPERIMENT=darwincrypto`
- **Purpose**: Uses Apple's CommonCrypto and CryptoKit frameworks
- **Platform**: macOS only
- **Available Since**: Go 1.24
- **Status**: Deprecated in 1.25
- **Replacement**: Enabled by default (via `systemcrypto`), set `MS_GO_NOSYSTEMCRYPTO: 1` if backend opt-out needed

## Removed Features

These features are removed and no longer available. See status for specific details.

### `GOEXPERIMENT=boringcrypto`
- **Purpose**: Used BoringSSL for cryptographic operations
- **Status**: Removed in Go 1.25
- **Replacement**: No direct replacement; consider using `systemcrypto` for system-backed crypto

### `GOEXPERIMENT=allowcryptofallback`
- **Purpose**: Previously allowed silent fallback to Go crypto if backend unsupported
- **Status**: Removed in Go 1.25
- **Replacement**: Set `MS_GO_NOSYSTEMCRYPTO: 1` if backend opt-out needed
