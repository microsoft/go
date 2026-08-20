# No-cgo OpenSSL Backend

This document describes how the Microsoft build of Go uses the no-cgo OpenSSL backend on Linux and FreeBSD.

> [!NOTE]
> The **no-cgo OpenSSL backend** is also known as the **cgo-less OpenSSL backend**.

The no-cgo backend complements, rather than replaces, the cgo OpenSSL backend.
The cgo backend is still available and is used when cgo is enabled.

## Overview

In Go 1.27 and later, the cgo-less OpenSSL backend is part of `systemcrypto` on Linux and FreeBSD.
It is selected automatically when cgo is disabled and the target architecture is supported.

> [!NOTE]
> In Go 1.26, this backend was available as the experimental `GOEXPERIMENT=ms_nocgo_opensslcrypto` feature on Linux only.
>
> In Go 1.27, the cgo-less backend is no longer experimental. The experiment has been removed and the cgo-less backend is selected automatically when needed.

This allows the use of OpenSSL without requiring cgo.

## Supported architectures

The cgo-less OpenSSL backend is supported on the following architectures.

On Linux:

- 386
- **amd64**
- arm
- **arm64**
- loong64
- ppc64le
- riscv64
- s390x (added in Go 1.27)

On FreeBSD (added in Go 1.27):

- **amd64**
- **arm64**

The set of supported architectures is limited because each architecture requires a unique assembly implementation to call OpenSSL.
Architectures are added based on demand and available resources.
To see existing requests or request support for additional architectures, use the [![](https://img.shields.io/github/labels/microsoft/go/Area-Nocgo)](https://github.com/microsoft/go/labels/Area-Nocgo) label.

## How the backend is selected

Starting in Go 1.27, these rules apply without any additional `GOEXPERIMENT` value.
In Go 1.26, they apply when `GOEXPERIMENT=ms_nocgo_opensslcrypto` is set.

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
