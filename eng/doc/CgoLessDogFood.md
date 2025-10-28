# Dogfooding GOEXPERIMENT=ms_nocgo_opensslcrypto

This document describes how to use the `ms_nocgo_opensslcrypto` experiment to build Go applications that use OpenSSL cryptography without requiring cgo.

## Overview

> [!WARNING]
> `GOEXPERIMENT=ms_nocgo_opensslcrypto` is still experimental, do not use in production yet.

The `ms_nocgo_opensslcrypto` experiment enables the Microsoft build of Go to use OpenSSL for cryptographic operations on Linux without requiring cgo.
This means you can build Go applications with `CGO_ENABLED=0`.

This is particularly useful for:

- **Cross-compilation**: Build for Linux targets from non-Linux hosts (e.g., Windows) or from linux/amd64 hosts to linux/arm64
- **Simplified builds**: Eliminate the need for C compilers
- **Reduce upstream Go divergence**: Makes it easier to start using the Microsoft build of Go using the same build scripts as upstream Go
- **cgo-less builds**: Enables building Go applications without cgo, which means fewer surprises when using libraries that modify their behavior based on cgo availability (e.g. `net`)

It is important to note that OpenSSL calls are still done in the same way as when cgo is enabled, that is, calls are done in a separate OS thread to avoid blocking the Go scheduler.
Do not expect performance improvements from disabling cgo.

## Platform Support

The `ms_nocgo_opensslcrypto` experiment is **only supported** when targetting the following platforms:

- `linux/amd64`
- `linux/arm64`

It is **not supported** on other platforms including Windows, macOS, or other Linux architectures.

## Prerequisites

### Runtime Requirements

There are no additional runtime requirements when using this experiment compared to the cgo-enabled OpenSSL support.

### Build Requirements

- `MS_GO_NOSYSTEMCRYPTO=1` environment variable can't be set when using this experiment.

There are no additional runtime requirements when using this experiment compared to the cgo-enabled OpenSSL support.

## Building Applications

### Basic Usage

To build an application with cgo-less OpenSSL support:

```bash
CGO_ENABLED=0 GOEXPERIMENT=ms_nocgo_opensslcrypto go build -o myapp main.go
```

### Cross-Compilation Example

Build a linux/arm64 binary from linux/amd64:

```bash
GOARCH=arm64 GOEXPERIMENT=ms_nocgo_opensslcrypto go build -o myapp main.go
```

## Testing Your Build

### Verify the Build

1. Check that your binary was built with the settings:

```bash
go version -m myapp
```

You should see the following entries in the output:

- `microsoft_systemcrypto=1`
- `GOEXPERIMENT=ms_nocgo_opensslcrypto`
- `CGO_ENABLED=0`

### Runtime Testing

On a Linux system with OpenSSL installed, run your application and verify it uses OpenSSL for cryptographic operations. You can test crypto functionality with a simple program:

```go
package main

import (
    "crypto/sha256"
    "fmt"
)

func main() {
    data := []byte("Hello, World!")
    hash := sha256.Sum256(data)
    fmt.Printf("SHA256: %x\n", hash)
}
```

We encourage you to use this experiment with your existing applications on an environment that resembles your production setup.

## Troubleshooting

### Build Fails with "unknown GOEXPERIMENT"

Ensure you're using the Microsoft build of Go. The `ms_nocgo_opensslcrypto` experiment is not available in upstream Go.

## Additional Resources

- [Cross-Platform Cryptography Documentation](./CrossPlatformCryptography.md) - Details on which algorithms are supported
- [Developer Guide](./DeveloperGuide.md) - Building the Microsoft build of Go from source
- [Migration Guide](./MigrationGuide.md) - General guidance for using system crypto features
