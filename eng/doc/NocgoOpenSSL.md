# Cgo-less OpenSSL Backend

This document describes the cgo-less OpenSSL backend for the Microsoft build of Go, available as an experimental feature starting in Go 1.26.

## Overview

In Go 1.26, there is a cgo-less experiment available for Linux: `ms_nocgo_opensslcrypto`.

In Go 1.27, the experiment will be removed and the cgo requirement for `systemcrypto` on Linux will be lifted by default.

This allows the use of OpenSSL without requiring cgo.

## Supported Architectures

Currently this experiment is supported on the following architectures:

- **386**
- **amd64**
- **arm**
- **arm64**
- **ppc64le**
- **riscv64**

The set of supported architectures is limited because each architecture requires a unique assembly implementation to call OpenSSL.
Architectures are added based on demand and available resources.
To see existing requests or request support for additional architectures, search for issues with the [`Area-Nocgo`](https://github.com/microsoft/go/labels/Area-Nocgo) label.

## How the Backend is Selected

If cgo is enabled (e.g., `CGO_ENABLED=1`), the cgo-based OpenSSL backend is always used.
The cgo-less backend is only used when cgo is disabled **and** you're on a supported architecture.

This means if you enable cgo for other reasons (e.g., linking your own C library or cross-compiling to an unsupported architecture), the crypto backend will use the cgo-based implementation.

## Experimental Status

While `systemcrypto` is a fully supported `GOEXPERIMENT` value (it is not "experimental"), `ms_nocgo_opensslcrypto` **is** experimental in Go 1.26 and may have limitations.
