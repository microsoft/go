# No-cgo OpenSSL Backend

This document describes how to enable and use the cgo-less OpenSSL backend for the Microsoft build of Go, available as an experimental feature starting in Go 1.26.

## Overview

In Go 1.26, there is a cgo-less experiment available for Linux: `ms_nocgo_opensslcrypto`.

> [!NOTE]
> While `systemcrypto` is a fully supported `GOEXPERIMENT` value (it is not "experimental"), `ms_nocgo_opensslcrypto` **is** experimental in Go 1.26 and may have limitations.

In Go 1.27, the experiment will be removed and the cgo requirement for `systemcrypto` on Linux will be lifted by default.

This allows the use of OpenSSL without requiring cgo.

## Supported architectures

Currently this experiment is supported on the following architectures:

- 386
- **amd64**
- arm
- **arm64**
- ppc64le
- riscv64

The set of supported architectures is limited because each architecture requires a unique assembly implementation to call OpenSSL.
Architectures are added based on demand and available resources.
To see existing requests or request support for additional architectures, use the [![](https://img.shields.io/github/labels/microsoft/go/Area-Nocgo)](https://github.com/microsoft/go/labels/Area-Nocgo) label.

## How the backend is selected

If cgo is enabled (e.g., `CGO_ENABLED=1`), the cgo-based OpenSSL backend is always used.
The cgo-less backend is only used when cgo is disabled **and** you're on a supported architecture.

This means if cgo is enabled by default on your platform or you enable cgo for other reasons (e.g., linking your own C library), the crypto backend will use the cgo-based implementation.
You can also intentionally enable cgo to successfully build for a platform without cgo-less OpenSSL support.
