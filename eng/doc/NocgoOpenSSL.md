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
- loong64
- ppc64le
- riscv64
- s390x (added in Go 1.27)

The set of supported architectures is limited because each architecture requires a unique assembly implementation to call OpenSSL.
Architectures are added based on demand and available resources.
To see existing requests or request support for additional architectures, use the [![](https://img.shields.io/github/labels/microsoft/go/Area-Nocgo)](https://github.com/microsoft/go/labels/Area-Nocgo) label.

## How the backend is selected

* If cgo is explicitly enabled with `CGO_ENABLED=1`, the cgo-based OpenSSL backend is used.
* If cgo is disabled with `CGO_ENABLED=0` and you're on a supported architecture, the cgo-less OpenSSL backend is used.
* If cgo is not explicitly enabled or disabled, then the cgo-less OpenSSL backend is used if the Go toolchain decides that cgo should be disabled. The are the rules at the time of writing:
  * cgo is disabled if the Go toolchain is build with `CGO_ENABLED=0`. Note that that's not currently the case for the Microsoft build of Go. 
  * cgo is disabled when cross-compiling.
  * cgo is diables if the `CC` environment variable is not set to an existing executable.

## Runtime dependencies

The cgo-less OpenSSL backend still relies in the C machinery to load OpenSSL at runtime and manage threads.

This is an exhaustive list of the runtime dependencies other than OpenSSL itself:

* `libc.so.6` for various C library functions. There is no minimum version requirement.
* `libdl.so.2` for loading OpenSSL at runtime using `dlopen`. There is no minimum version requirement.
* `libpthread.so.0` for managing Go's threads. There is no minimum version requirement.

Note that `libdl.so.2` and `libpthread.so.0` functionality is already provided by `libc.so.6` since glibc 2.34.
The Microsoft build of Go supports platforms with older versions of glibc, so it still links to `libdl.so.2` and `libpthread.so.0` directly.
If your platform doesn't provide these libraries, you can create them as symlinks to `libc.so.6` to satisfy the dependencies, e.g. `ln -s libc.so.6 libdl.so.2` and `ln -s libc.so.6 libpthread.so.0`.
