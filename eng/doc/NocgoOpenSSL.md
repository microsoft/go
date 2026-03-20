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
* If cgo is disabled with `CGO_ENABLED=0`, then:
  * If you're on a supported architecture, the cgo-less OpenSSL backend is used.
  * If you're on an unsupported architecture, the build fails.
* If cgo is not explicitly enabled or disabled, then the cgo-less OpenSSL backend is used if the Go toolchain decides that cgo should be disabled. The rules are officially described by [cmd/cgo](https://pkg.go.dev/cmd/cgo). This is a summary, at the time of writing (2026-03-19):
  * cgo is disabled if the Go toolchain is built with `CGO_ENABLED=0`. Note that that's not currently the case for the Microsoft build of Go. 
  * cgo is disabled when cross-compiling.
  * cgo is disabled if the `CC` environment variable is not set to an existing executable.

## Runtime dependencies

The cgo-less OpenSSL backend still relies on the C machinery to load OpenSSL at runtime and manage threads.

The following are the expected runtime dependencies other than OpenSSL itself on glibc-based systems:

* `libc.so.6` for various C library functions.
* `libdl.so.2` for loading OpenSSL at runtime using `dlopen`.
* `libpthread.so.0` for managing Go's threads.

> [!NOTE]
> The `libdl.so.2` and `libpthread.so.0` functionality is already provided by `libc.so.6` since glibc 2.34.
> The Microsoft build of Go supports platforms with older versions of glibc, so it still links to `libdl.so.2` and `libpthread.so.0` directly.
>
> There is no runtime dependency on the same libc that the program was built with. You can, for example, build a program on a system with glibc 2.34 or later and run it on a system with an older glibc version.
>
> If your platform doesn't provide these libraries, the preferred solution is to install the appropriate runtime or compatibility packages so that `libdl.so.2` and `libpthread.so.0` are available in standard system library directories (for example `/lib` or `/usr/lib`).
>
> As an advanced workaround, you may instead symlink `libdl.so.2` and `libpthread.so.0` to `libc.so.6` in a directory searched by the dynamic linker (for example, a system library directory) and update the loader cache if required (for example by running `ldconfig`); this typically requires root privileges and should only be done if you understand the implications for your system's C library.
