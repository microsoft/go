This directory contains documentation about FIPS, details about the FIPS implementation in the Microsoft build of Go, and using system-provided cryptography via the Go standard library.

* README.md (this file): an overview of the design and how to use it.
* [**FIPS 140 User Guide** (UserGuide.md)](UserGuide.md): notes on FIPS compliance of specific crypto APIs.

See also:

* [The Migration Guide](../MigrationGuide.md).  Includes direct guidance on how to migrate an existing Go app to use the Microsoft build of Go and decide whether this is necessary.
* [Cross-Platform Cryptography in the Microsoft build of Go](../CrossPlatformCryptography.md). A digestible overview of the information in the *FIPS 140 User Guide*.
* [The Microsoft build of Go README](../../../README.md). Background information about the Microsoft build of Go and how to acquire it.
* [The Microsoft internal policy `Microsoft.Security.Cryptography.10010`.][msc10010]

# Crypto FIPS 140 support

## Background

FIPS 140 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance and specifically FIPS 140-3 certification may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

The upstream plan to support building FIPS compliant Go apps is described in [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140) and [crypto: obtain a FIPS 140-3 validation (golang/go#69536)](https://github.com/golang/go/issues/69536).
Go 1.24 delivered some major steps in this plan: the crypto module itself (written in Go and Go assembly), the concept of FIPS mode in the Go runtime, and new toolset settings.

This approach is unique and offers some advantages, and we encourage Go developers who require FIPS 140 compliance to evaluate this official feature and use it.
However, we determined that this approach doesn't align with Microsoft internal cryptography strategy and policies.

Prior to Go 1.24, Google maintained the [goexperiment](https://pkg.go.dev/internal/goexperiment) `boringcrypto`, that uses cgo and BoringSSL to implement various crypto primitives.
As BoringSSL is FIPS 140 certified, an application built using this flag is more likely to be FIPS 140 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140 standard.

In addition to that, the `boringcrypto` experiment also provides a mechanism to restrict all TLS configuration to FIPS-compliant settings.
The effect is triggered by importing the `crypto/tls/fipsonly` package anywhere in a program, and as of Go 1.24, this mode is controlled by the Go runtime's FIPS mode.

## Microsoft build of Go FIPS compliance

The Microsoft build of Go modifies the Go runtime to call into a platform-provided cryptographic library to implement crypto primitives rather than use the standard Go crypto implementations.
Depending on the platform, this is done using cgo or syscalls.
This allows Go programs to use a platform-provided FIPS 140 certified crypto library.

On Linux, the fork uses [OpenSSL](https://www.openssl.org/) through the [golang-fips/openssl] module. On Windows, [CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/about-cng), using [go-crypto-winnative]. On macOS, [CommonCrypto](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/Common%20Crypto.3cc.html) and [CryptoKit](https://developer.apple.com/documentation/cryptokit) using [go-crypto-darwin]. Similar to BoringSSL, certain OpenSSL, CNG and CommonCrypto/CryptoKit versions are FIPS 140 certified.

> [!IMPORTANT]
> An application built with Microsoft's Go toolchain and running in FIPS compatible mode is not FIPS compliant _per-se_.
> It is the responsibility of the application development team to use FIPS-compliant crypto primitives and workflows.
>
> For compatibility reasons, the modified crypto runtime will fall back to Go standard library crypto if it cannot provide a FIPS-compliant implementation, e.g. when hashing a message using `crypto/md5` hashes or when using an AES-GCM cipher with a non-standard nonce size.

## Configuration overview

The Microsoft build of Go provides several ways to configure the crypto backend and its behavior.
These are described in the following sections in detail.

- Build-time configuration (`go build`):
  - [`GOEXPERIMENT=<backend>crypto` environment variable](#usage-build)
  - [`goexperiment.<backend>crypto` build tag](#usage-build)
  - [`requirefips` build tag](#build-option-to-require-fips-mode)
  - [`GOFIPS140=latest` environment variable](#build-option-to-require-fips-mode)
  - [`import _ "crypto/tls/fipsonly"` source change](#tls-with-fips-compliant-settings)
- Runtime configuration:
  - [`GOFIPS` environment variable](#usage-runtime)
  - [`GODEBUG=fips140` setting](#usage-runtime)
  - (OpenSSL backend) [`GO_OPENSSL_VERSION_OVERRIDE` environment variable](#runtime-openssl-version-override)
  - (OpenSSL backend) [`/proc/sys/crypto/fips_enabled` file containing `1`](#linux-fips-mode-openssl)
  - (CNG backend) [Windows registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` dword value `Enabled` set to `1`](#windows-fips-mode-cng)

## Usage: Common configurations

The modified Go runtime is typically used to accomplish one of two goals: complying with [internal Microsoft crypto policies][msc10010] or creating a FIPS compliant app.
The following table summarizes common configurations and how suitable each one is for these goals.

> [!NOTE]
> This document assumes the use of a supported version of the Microsoft build of Go: 1.25 or later.

> [!NOTE]
> Since Go 1.25, `systemcrypto` is enabled by default on Linux and Windows. There is no need to manually enable using OpenSSL/CNG under the hood anymore. See also [the Go 1.25 changelog](#go-125-aug-2025). Since Go 1.26, `systemcrypto` is also enabled by default on macOS.

> [!TIP]
> If an app uses no cryptography, FIPS compliance is not relevant and the internal Microsoft crypto policy doesn't apply.

| Build-time config | Runtime config | Internal Microsoft crypto policy | FIPS behavior |
| --- | --- | --- | --- |
| Default | Default | Compliant | Can be used to create a compliant app. FIPS mode is determined by system-wide configuration. Make sure you are familiar with your platform's system-wide FIPS switch, described in [Usage: Runtime](#usage-runtime). |
| `GOEXPERIMENT=systemcrypto` | Default | Compliant | Can be used to create a compliant app. The `GOEXPERIMENT` setting is redundant because `systemcrypto` is enabled by default. |
| Default | `GODEBUG=fips140=on` or `GOFIPS=1` | Compliant | Can be used to create a compliant app. Depending on platform, the app enables FIPS mode, ensures it is already enabled, or doesn't do any additional checks. The app panics if there is a problem. See [Usage: Runtime](#usage-runtime). |
| Default | `GODEBUG=fips140=only`, Go 1.27+ | Compliant | Same as `fips140=on`, but also panics if a non-FIPS-approved algorithm is used. Note: if the backend does not support a particular algorithm, the call panics rather than falling back to Go standard library crypto. See [Cross-Platform Cryptography](../CrossPlatformCryptography.md) to check algorithm support per platform, and [Usage: Runtime](#usage-runtime). |
| Default | `GO_OPENSSL_VERSION_OVERRIDE=1.1.1k-fips` | Compliant | Can be used to create a compliant app. On Linux, this environment variable causes the runtime to load `libcrypto.so.1.1.1k-fips` instead of using the automatic search behavior. This environment variable has no effect on Windows or macOS. |
| `-tags=requirefips` | Default | Compliant | Can be used to create a compliant app. The behavior is the same as `GODEBUG=fips140=on` and `GOFIPS=1`, but no runtime configuration is necessary. See [the `requirefips` section](#build-option-to-require-fips-mode) for more information on when this "locked-in" approach may be useful rather than the flexible approach. |
| `MS_GO_NOSYSTEMCRYPTO=1` or `GOEXPERIMENT=nosystemcrypto` | Default | Not compliant | Crypto usage is not FIPS compliant. |
| `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=ms_nocgo_opensslcrypto`, Go 1.26 | Default | Compliant | [Experimental](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/NocgoOpenSSL.md). Crypto usage is FIPS compliant. |

Some configurations are invalid and intentionally result in a build error or runtime panic:

| Build-time config | Runtime config | Behavior |
| --- | --- | --- |
| `MS_GO_NOSYSTEMCRYPTO=1` and `-tags=requirefips` | | The build fails. A crypto backend must be specified to enable FIPS features. |
| `GOOS=linux CGO_ENABLED=0` | | The build fails. Cgo is required to use the OpenSSL backend. |

## Usage: Build

The default behavior of the Microsoft build of Go is to use a platform-provided cryptographic library using `systemcrypto`.
See the [Migration Guide](/eng/doc/MigrationGuide.md) for more information on incorporating the Microsoft build of Go into your build system.

`systemcrypto` modifies the Go runtime included in the program to use the specified platform-provided cryptographic library whenever it calls a Go standard library crypto API.
If `systemcrypto` is disabled (see [build option to use Go crypto](#build-option-to-use-go-crypto)), Go standard library cryptography is used.

> [!NOTE]
> "Experiment" doesn't indicate the FIPS features are experimental. The original intent of `GOEXPERIMENT` is to use it to enable experimental features in the Go runtime and toolchain, but we and Google are now using `GOEXPERIMENT` for this FIPS-related feature because the mechanism itself perfectly fits our needs.

> [!NOTE]
> Prior to Go 1.27, per-platform experiments (`opensslcrypto`, `cngcrypto`, `darwincrypto`) were available. These have been removed in Go 1.27. Use `systemcrypto` instead, which automatically selects the appropriate backend based on the target platform.

The `systemcrypto` experiment uses platform-specific code via build constraints. The platform is determined by the target platform (`GOOS`), and the appropriate system cryptography library is used:

| Target platform | Library |
| --- | --- |
| Linux | OpenSSL |
| Windows | CNG |
| macOS | CommonCrypto & CryptoKit |

In a cross-build scenario, such as using Linux to build an app that will run on Windows, `GOOS=windows` will correctly use CNG-based code for the `systemcrypto` backend.

A cross-build to Windows or macOS will typically work, because these backends use approaches like syscalls to call the crypto library rather than cgo.
A cross-build to Linux, however, is more complicated (perhaps infeasible), because its backend uses cgo.

The Linux backends' use of cgo also introduces the glibc compatibility problem.
Building a cgo program on a distro that uses a new glibc version and running that program on a distro with an older glibc version may fail due to missing glibc symbols.
This is often mitigated by building on a distro with the oldest expected glibc version.
We have also successfully used a rootfs to build on an older glibc version (and cross-compile arm64 binaries on an amd64 machine), with rough notes available in [microsoft/go#1866](https://github.com/microsoft/go/issues/1866).

> [!TIP]
> Go 1.26 introduces an experiment to use OpenSSL on Linux without cgo.
> See [No-cgo OpenSSL Backend](/eng/doc/NocgoOpenSSL.md) for more information.

If a crypto backend is selected but isn't supported, the build fails.
For example, attempting to use the OpenSSL backend without cgo enabled results in a build error.

For more information about disabling the crypto backend, see [build option to use Go crypto](#build-option-to-use-go-crypto).

## Usage: Runtime

A program built with `systemcrypto` always uses the system-provided cryptography library for supported crypto APIs: OpenSSL on Linux, CNG on Windows, and CommonCrypto/CryptoKit on macOS. If the platform's crypto library can't be found or loaded, the Go program panics during initialization.

The following sections describe how to enable FIPS mode and the effect of the `GODEBUG=fips140=on` and `GOFIPS=1` settings on each supported platform.

The Microsoft build of Go detects your FIPS mode preference by evaluating this list.

- If environment variable setting `GODEBUG=fips140=on` is found: Enabled ✅
  - More specifically, if [`GODEBUG`](https://go.dev/doc/godebug) contains `fips140=on`.
  - This is the recommended way to set your FIPS preference.
- If the environment variable `GOFIPS` is set to:
  - `1`: Enabled ✅
- If the environment variable `GOLANG_FIPS` is set to:
  - `1`: Enabled ✅
- If a platform-specific preference is detected: Enabled ✅
  - See the following sections for per-platform details.
- If the [build option to require FIPS mode](#build-option-to-require-fips-mode) is enabled: Enabled ✅
- Otherwise: no preference detected. ❔

If FIPS mode preference is Enabled ✅, then:

- If the platform's crypto library is not in FIPS mode, the program panics during initialization.
  - This may help detect and refuse to run with incorrectly configured environments.
- The program enables [Go Runtime FIPS mode](#go-runtime-fips-mode).

The Go runtime FIPS mode may be important to distinguish its FIPS mode from the system FIPS mode or crypto engine's FIPS mode.
The [Go Runtime FIPS mode](#go-runtime-fips-mode) section describes this in more detail.

Since Go 1.27, there is also `GODEBUG=fips140=only`.
It acts as `GODEBUG=fips140=on`, but also makes a best effort to panic if a non-FIPS 140-3 compliant algorithm is used.

> [!NOTE]
> When `fips140=only` is set with a system crypto backend, the enforcement depends on the backend's algorithm support.
> If the backend does not support a particular FIPS-approved algorithm (e.g. SHA-512/224 on macOS, or CTR mode on macOS), a call to that algorithm will panic rather than falling back to the Go standard library implementation.
> This means that `fips140=only` may restrict the set of usable algorithms compared to `fips140=on`, depending on the platform.
> See [Cross-Platform Cryptography](../CrossPlatformCryptography.md) to check which algorithms are supported on each platform.

> [!NOTE]
> The `GODEBUG`, `GOFIPS`, and `GOLANG_FIPS` options described in this section have no effect at build time, only runtime. When the Go program starts up, it examines its environment variables and other platform-specific configurations. This is normally the desired behavior. See [`requirefips`](#build-option-to-require-fips-mode) for info about an optional build tag that may affect FIPS mode.

### Linux FIPS mode (OpenSSL)

The Linux Kernel FIPS mode is read to determine the platform-specific FIPS preference on Linux.
The Go runtime reads the content of `/proc/sys/crypto/fips_enabled`, and if it's `1`, then the platform preference is to enable FIPS.

> [!NOTE]
> In a Linux container, the content of `/proc/sys/crypto/fips_enabled` is shared with the container host.
> This is because the kernel is shared.

If OpenSSL is not using a FIPS-compliant engine or provider, the Go runtime considers OpenSSL to not be in FIPS mode.
The Go runtime makes no attempt to modify OpenSSL FIPS mode.

For more information about the standard OpenSSL FIPS behavior, see https://www.openssl.org/docs/fips.html.

> [!TIP]
> You might want to test FIPS mode app behavior, perhaps on an otherwise non-FIPS system.
> OpenSSL and some Linux distros provide mechanisms to help run this type of test.
>
> For OpenSSL 3, see [`OPENSSL_CONF`](https://docs.openssl.org/3.0/man5/config/) to change to a FIPS crypto provider.
>
> For Azure Linux, see:
>
> - [`OPENSSL_FORCE_FIPS_MODE=1`](https://github.com/microsoft/azurelinux/blob/bfd36df1487511735dbd5fade66b0b613c89b46a/SPECS/openssl/0009-Add-Kernel-FIPS-mode-flag-support.patch#L34).
> - [(Microsoft-internal documentation) "How do I enable FIPS on my Azure Linux Azure Marketplace VM Image?"](https://eng.ms/docs/products/azure-linux/overview/security/fips#1-how-do-i-enable-fips-on-my-azure-linux-azure-marketplace-vm-image)

### Windows FIPS mode (CNG)

The platform-specific FIPS preference on Windows is determined by the result of calling [BCryptGetFipsAlgorithmMode](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetfipsalgorithmmode).

To enable FIPS mode on Windows, [enable the Windows FIPS policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#step-3-enable-the-fips-security-policy).

For testing purposes, Windows FIPS policy can be enabled via the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`, dword value `Enabled` set to `1`.

CNG cryptographic primitives are FIPS compliant by default.
Since Go 1.26, setting the enabled FIPS preference will not cause a panic on Windows even if the Windows FIPS policy is not enabled.

### macOS FIPS mode (CommonCrypto/CryptoKit)

A platform-specific FIPS preference is never detected on macOS.
There is no standard system-provided mechanism to indicate FIPS mode on macOS.

To instruct Go to run in [Go Runtime FIPS mode](#go-runtime-fips-mode) on macOS, manually setting an enabled preference is necessary.

macOS cryptographic primitives are FIPS compliant by default.
This means setting the enabled FIPS preference will never cause a panic on macOS.
However, for compatibility reasons (see [the Go Runtime FIPS mode](#go-runtime-fips-mode)), the Microsoft build of Go doesn't enable FIPS settings by default on macOS.

See the [About Apple security certifications](https://support.apple.com/guide/certifications/about-apple-security-certifications-apc30d0ed034/1/web/1.0) page for more information.

### Go Runtime FIPS mode

The Go runtime has a FIPS mode.
It is enabled by `GODEBUG=fips140=on` (or any equivalent).
It can be checked by calling [crypto/fips140.Enabled](https://pkg.go.dev/crypto/fips140#Enabled).

This mode has many effects described in [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140).
One notable effect is that the Go runtime TLS stack will only use FIPS-compliant settings.

The [FIPS mode preference system](#usage-runtime) automatically enables Go runtime FIPS mode when necessary.
For example, if a Linux system is in system-wide FIPS mode, the Microsoft build of Go ensure OpenSSL is in FIPS mode and enables the Go runtime FIPS mode.

> [!WARNING]
> On macOS, there is no such thing as system-wide FIPS mode.
> That is: there is no universal way to configure a macOS system to indicate that all programs that run on that system should follow FIPS requirements.
> As a result, the Microsoft build of Go has no reliable indicator that the Go runtime FIPS mode should be enabled.
>
> For compatibility reasons, the Microsoft build of Go defaults to not enabling FIPS settings.
> For example, FIPS settings may prevent an application from connecting to a server that doesn't support FIPS-compliant TLS.
>
> To make the TLS stack use FIPS-compliant settings on macOS, `GODEBUG=fips140=on` (or an equivalent preference assignment) must be set explicitly.

## Usage: Extra configuration options

### Build option to require FIPS mode

FIPS mode preference is normally determined at runtime, but the `GOFIPS140=latest` and `requirefips` options can be used to make a program (that depends on the `crypto` package) always require FIPS mode and panic if FIPS mode is not enabled:

- The `requirefips` build tag is available since Go 1.21. See [the "GOFLAGS" example in the build section](#modify-the-build-command).
- The `GOFIPS140=latest` environment variable is available since Go 1.24.

Most programs aren't expected to use these options. Determining FIPS mode at runtime is normal for FIPS compliant applications. This allows the same binary to be deployed to run in both FIPS compliant contexts and non-FIPS contexts, and allows it to be bundled with other binaries that can also run in both contexts. However, the build option is useful in some cases:

- Dependence on environment variables like `GODEBUG` and `GOFIPS` in any way may be undesirable.
- The program's documentation can state it will always run in FIPS mode without any nuance about environment variables.
- If the program is used by someone unfamiliar with the system they're configuring, the panic will help catch mistakes before they become a problem.

### Build option to use Go crypto

The Microsoft build of Go uses the `systemcrypto` backend by default to provide `crypto` functionality.
It's possible to disable `systemcrypto` and use the Go standard library's implementation of cryptography instead.

> [!CAUTION]
> Within Microsoft, disabling `systemcrypto` should only be done in exceptional circumstances under a documented exception.
>
> More information about the Microsoft cryptography policy can be found at [Microsoft.Security.Cryptography.10010 on the Liquid Microsoft-internal site.][msc10010]
>
> If you haven't already, check the [Migration Guide](/eng/doc/MigrationGuide.md) to find common issues and fixes.

> [!TIP]
> If your project don't use the `crypto` package at all, `systemcrypto` is not included in your program.
> This is an alternative to complying with cryptography policies: refactor the code to not use any cryptography.
> While this isn't possible for many types of projects, it may be an ideal approach for tools that only run on a local machine.
>
> For example, when computing a hash for non-cryptographic purposes, there are several alternatives in the Go standard library that don't require a crypto backend, such as `hash/fnv` or `hash/maphash`.

If it's acceptable to become incompliant with the internal Microsoft crypto policy and FIPS, you can use the Go standard library cryptography implementation by disabling the `systemcrypto` backend:

- With Go 1.25.2 or later, set the `MS_GO_NOSYSTEMCRYPTO` environment variable to `1`.
- With Go 1.25 or later, set the `GOEXPERIMENT` environment variable to `nosystemcrypto`.

Both of the above methods are supported, but we encourage using `MS_GO_NOSYSTEMCRYPTO` instead of `GOEXPERIMENT`:

- `GOEXPERIMENT=nosystemcrypto` may make your *build command* incompatible with the official Go toolset. ([microsoft/go#1880](https://github.com/microsoft/go/issues/1880))
- `MS_GO_NOSYSTEMCRYPTO=1` doesn't involve the `GOEXPERIMENT` mechanism. It's simpler to use and to incorporate into any build process.

> [!WARNING]
> `MS_GO_NOSYSTEMCRYPTO=1` has precedence over `GOEXPERIMENT` values.
> It will disable the backend even if `GOEXPERIMENT=systemcrypto` is set.
>
> Specifically, `MS_GO_NOSYSTEMCRYPTO=1 GOEXPERIMENT=systemcrypto go build .` builds a program that uses Go standard library cryptography.

> [!NOTE]
> Your program may use Go crypto even if `systemcrypto` is enabled.
> If the selected backend doesn't support an API or the specific arguments used to call it, the call may fall back to using standard Go crypto at runtime.
> See the [FIPS User Guide](UserGuide.md) for more information.

### Runtime OpenSSL version override

On Linux, the Go runtime automatically loads the OpenSSL shared library `libcrypto` using [dlopen] when initializing. Therefore, dlopen's shared library search conventions also apply here.

The `libcrypto` shared library file name varies among different platforms, so a best effort is done to find and load the right file:

- The base name is always `libcrypto.so.`
- Well-known version strings are appended to the base name in this order:
  - Since Go 1.25: `3` -> `1.1` -> `11` -> `111`.
  - Prior to Go 1.25: `3` -> `1.1` -> `11` -> `111` -> `1.0.2` -> `1.0.0`.
- This may find multiple libraries installed on the machine, so to pick one:
  - A matching library with FIPS mode on by default (e.g. set by system configuration) is chosen immediately.
  - If none have FIPS mode on by default, the first match is used.

This algorithm can be overridden by setting the environment variable `GO_OPENSSL_VERSION_OVERRIDE` to the desired version string. For example, `GO_OPENSSL_VERSION_OVERRIDE="1.1.1k-fips"` makes the runtime look for the shared library `libcrypto.so.1.1.1k-fips` before running the checks for well-known versions.

## Usage: GOEXPERIMENTs and backend build tags

### Multiple GOEXPERIMENTS

When using `GOEXPERIMENT`, you can enable other non-crypto experiments simultaneously using a comma separator, e.g. `GOEXPERIMENT=systemcrypto,loopvar`. Combining other experiments with `systemcrypto` is supported.

For more information about other Go experiments, read the output of the command `go doc goexperiment.Flags` to see the experiments available in your specific build of the Go toolset, or check [the online goexperiment package doc](https://pkg.go.dev/internal/goexperiment) to see the options for other versions.

### Build tags

Selecting most `GOEXPERIMENT`s can also be done by setting the corresponding `goexperiment.*` build tag. This is supported for all crypto backends.

For example, `go build -tags=goexperiment.systemcrypto` command will enable the same backend as setting `GOEXPERIMENT=systemcrypto` then running the build command.

> [!NOTE]
> Experiments can't be disabled by a build tag, see [Disabling `systemcrypto`](../MigrationGuide.md#disabling-systemcrypto) for how to disable `systemcrypto`.
> For example, `go build -tags=goexperiment.nosystemcrypto` has no effect.

### Conditional behavior if a crypto backend is enabled

Normally this is not necessary, but a shared package may need to change its implementation when compiled with a crypto backend rather than the ordinary Go backend. For example, the library may need to remove use of cryptographic algorithms that would not be permitted by FIPS, in a way that will still allow the library to function. This is done using [build constraints](https://pkg.go.dev/go/build#hdr-Build_Constraints), also known as build tags.

- `//go:build goexperiment.systemcrypto` conditionally includes the source file if *any* crypto backend is enabled.
- `//go:build !goexperiment.systemcrypto` includes the file if *no* crypto backend is enabled.

The `goexperiment.systemcrypto` tag's behavior is implemented in a patch to the build system in the Microsoft build of Go.
It is not available in builds of upstream Go.
The constraint `//go:build !goexperiment.systemcrypto` won't cause a build to fail with upstream Go, but it is always satisfied.
The constraint also doesn't interact with the FIPS features introduced in Go 1.24.

## Features

### No code changes required

The steps above don't require any changes to the app's source code. These steps change the Go runtime, but the crypto APIs are the same. The Go runtime will then favor OpenSSL/CNG crypto primitives over the Go standard library implementation.

Note that while using a FIPS-certified cryptographic module is a FIPS requirement, it is not the only one. Code changes may be needed for a specific app to conform to FIPS in ways that can't be fixed simply by using a modified Go runtime. For example, algorithms and key sizes forbidden by FIPS 140 need to be removed from the app without breaking it. Misuse of approved algorithms must also be fixed. For more information, see the [FIPS User Guide](UserGuide.md).

### Multiple OpenSSL versions allowed

On Linux, the Go runtime supports multiple OpenSSL versions. It discovers and picks the OpenSSL version to use at runtime, not compile time. This helps make the feature easy to incorporate in existing builds.

Not all OpenSSL versions are supported. OpenSSL does not maintain ABI compatibility between different releases, even if only the patch version is increased, it needs specific attention to implement support. The relative importance of each version also results in a different amount of automated testing that has been implemented for various supported version. These are supported versions and the amount of automated validation for each one:

- OpenSSL 1.1.1: the Microsoft CI builds official releases and runs the Go toolset test suite with this version.
- OpenSSL 1.1.0, 1.1.1, and 3.0.2: the [golang-fips/openssl] and [go-crypto-openssl] repository CI tests basic operation, but not the integration with the Go runtime.
  - Prior to Go 1.25, this list includes 1.0.2.

Versions not listed above are not supported at all.

> [!NOTE]
> Any build of OpenSSL might have various [OpenSSL features] enabled or disabled, diverging from the default configuration. The Microsoft build of Go does not support all possible OpenSSL configurations. Some may cause the Go runtime to panic during initialization or not work as expected.
>
> The Go runtime is tested with the default configuration of each supported OpenSSL version and with the OpenSSL configurations in the [Azure Linux] 2 and [Azure Linux] 3 distributions.

### No static linking

Microsoft's [internal policy `Microsoft.Security.Cryptography.10010`][msc10010] forbids static linking to OpenSSL.
For Linux, we use [dlopen] when initializing OpenSSL, satisfying this requirement.

> [!NOTE]
> The Microsoft internal policy forbids "static linking" and requires "dynamic linking", but [dlopen] is often considered to be in a distinct category called "dynamic loading" (https://stackoverflow.com/a/45959845).
> We have discussed this with the Crypto Board, and the [dlopen] approach does satisfy the policy requirement.
> The key is that the Go program uses the OpenSSL library provided by the OS/environment and doesn't need to be rebuilt to take an OpenSSL update.

> [!NOTE]
> It's a relatively common practice in the Go ecosystem to statically link all dependencies of a Go program to produce a single binary that can run standalone.
> This can simplify deployment and allows Go apps to run when a dynamic loader isn't present, such as in `scratch`-based containers.
> Unfortunately, the internal policy requirement means this isn't possible to do with a Go program that uses cryptography: other dependencies can be statically linked, but not OpenSSL.
>
> If you are responsible for a Go app in Microsoft and it's absolutely necessary that the app is fully statically linked, contact the Crypto Board for more details.
>
> We have discussed support for static linking in [microsoft/go#744 *OpenSSL static linking proposal*](https://github.com/microsoft/go/issues/744)
> However, we learned this would not be considered compliant with Microsoft policies and it isn't possible with the way OpenSSL 3 is designed to load providers, so we don't have any plans to implement it.

The policy's requirements and recommendations for Windows and macOS don't specifically mention linking, but for clarity: the Microsoft build of Go never statically links any platform's crypto libraries.

### Portable OpenSSL

The OpenSSL version present when building a program does not have to match the OpenSSL version used when running it.
In fact, OpenSSL doesn't need to be present on the builder at all if the built program isn't executed on that system.
*Dynamic loading at runtime* rather than *dynamic linking at build-time* makes this possible.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain.

### TLS with FIPS-compliant settings

The Go TLS stack will automatically use crypto primitives from the selected crypto backend. Yet, this isn't enough for FIPS compliance: the FIPS 140 standard places additional restrictions on TLS communications, mainly on which cyphers and signers are allowed. Note that this can reduce compatibility with old devices that do not support modern cryptography techniques such as TLS 1.2.

The Microsoft build of Go automatically enforces that `crypto/tls` and `crypto/x509` only use FIPS-compliant settings when running in FIPS mode.
This differs from upstream's BoringCrypto backend, which requires you to import `crypto/tls/fipsonly` to apply the FIPS-mandated restrictions.
The Microsoft build of Go does this automatically to reduce the source code changes necessary to produce a FIPS-compliant Go application, and to make it easier to use the same binary in both FIPS and non-FIPS environments.

> [!NOTE]
> The new upstream Go 1.24 approach ([FIPS 140-3 Compliance](https://go.dev/doc/security/fips140)) also improves upon the BoringCrypto backend by automatically enforcing FIPS-compliant settings in the Go TLS stack when Go is running in the newly introduced FIPS mode.

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- All crypto stubs are based on upstream Go's [boringcrypto implementation](https://pkg.go.dev/crypto/internal/boring).
- The mapping between BoringSSL and OpenSSL APIs is taken from Fedora's [Go fork](https://pagure.io/go).
- Portable OpenSSL implementation ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Disclaimer

A program running in FIPS mode can claim it is using a FIPS-certified cryptographic module, but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Changelog

This list of major changes is intended for quick reference and for access to historical information about versions that are no longer supported. The behavior of all in-support versions are documented in the sections above with notes for version-specific differences where necessary.

### Go 1.27 (Aug 2026)

- Support for `GODEBUG=fips140=only` has been added. It acts as `fips140=on`, but also panics if a non-FIPS-approved algorithm is used.
- The per-platform GOEXPERIMENTs (`opensslcrypto`, `cngcrypto`, `darwincrypto`) have been removed.
  - Using any of the removed experiments will result in a build error.
  - The `systemcrypto` GOEXPERIMENT has been the preferred way to select a crypto backend since it was introduced in Go 1.21. It is now the only way.
  - The build tags (build constraints) associated with the removed GOEXPERIMENTs are no longer supported.
    - The per-platform tags are not set by the Microsoft build of Go when `systemcrypto` is enabled.
    - Manually using `-tags` to enable a per-platform backend tag no longer has any effect on the standard library.
    - The `goexperiment.systemcrypto` build tag remains supported, and its behavior has not changed.

### Go 1.26 (Feb 2026)

- The `systemcrypto` goexperiment is now enabled by default on macOS.
- The macOS backend is no longer "preview" and is now fully supported.
- `systemcrypto` can be [disabled at build time](#build-option-to-use-go-crypto) by setting the `MS_GO_NOSYSTEMCRYPTO` environment variable to `1`.
- Setting the enabled FIPS preference will not cause a panic on Windows even if the Windows FIPS policy is not enabled.

### Go 1.25.2 (Oct 2025)

- `systemcrypto` can be [disabled at build time](#build-option-to-use-go-crypto) by setting the `MS_GO_NOSYSTEMCRYPTO` environment variable to `1`.

### Go 1.25 (Aug 2025)

- The `systemcrypto` goexperiment is now enabled by default on Windows and Linux. To disable it, set `GOEXPERIMENT=nosystemcrypto`.

- Running `go version -m` on a binary which uses a system crypto backend now shows the `microsoft_systemcrypto=1` build setting.

- The build-time backend compatibility check now only runs when a crypto package is required for the build.
  - If your app doesn't depend on a crypto package, you may, for example, use `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto`.
  - If your app doesn't use a crypto package and you make a change that introduces a crypto package dependency, you will only encounter a compatibility check failure after the change. The change may be in your transitive dependencies: for example, depending on a new module that uses `crypto/sha256` may trigger the compatibility check. This is undesirable, but it's necessary to enable flexibility.

- `GOFIPS=0` support has been removed. It now has no effect.

- `GOEXPERIMENT=boringcrypto` has been removed.

- `GOEXPERIMENT=allowcryptofallback` has been removed. Instead, if it's necessary to opt out from using a system crypto backend, use `GOEXPERIMENT=nosystemcrypto`. This is an internal mechanism that is not intended for use when building a Go application. This document has always recommended against using it, so we anticipate that this change won't affect users of the Microsoft build of Go. Please [contact the maintainers of the Microsoft build of Go](https://github.com/microsoft/go/blob/microsoft/main/SUPPORT.md) if you need to use it so we can understand the scenario and help find a safer alternative.

- The OpenSSL backend [no longer supports OpenSSL 1.0](https://github.com/golang-fips/openssl/issues/244). The supported versions are now OpenSSL 1.1.0, 1.1.1, and 3.x.

### Go 1.24 (Feb 2025)

See the [Microsoft build of Go 1.24 FIPS changes](https://devblogs.microsoft.com/go/go-1-24-fips-update/) blog post for a summary of the Feb 2025 changes.

- Introduces macOS crypto backend (removed as a separate experiment in Go 1.27, now part of `systemcrypto`).
- Support `GODEBUG=fips140=on` as an alias for `GOFIPS=1`.
- `GOFIPS=1` no longer tries to enable FIPS mode on Linux. It will now panic if FIPS mode is not enabled.
- `GOFIPS=0` no longer tries to disable FIPS mode on Linux. It will now panic if FIPS mode is enabled.
- Support for the `GOFIPS` environment variable may be removed in a future major release.

### Go [1.22.9-2](https://github.com/microsoft/go/releases/tag/v1.22.9-2) and [1.23.3-2](https://github.com/microsoft/go/releases/tag/v1.23.3-2) (Dec 2024)

- Adds compatibility with changes that [Azure Linux] 3 made to the OpenSSL configuration, specifically the change to use [SCOSSL](https://github.com/microsoft/SymCrypt-OpenSSL). The SCOSSL-related Azure Linux packages must also be up to date for compatibility, at least `SymCrypt-103.6.0-1` and `SymCrypt-OpenSSL-1.6.1-1`.

### Go 1.22 (Feb 2024)

- Automatically enforce that `crypto/tls` and `crypto/x509` only use FIPS-approved settings when running in FIPS mode.

### Go 1.21 (Aug 2023)

- Adds build errors if a crypto backend is selected but not supported.
  - Before 1.21, selecting an unsupported backend causes *silent crypto backend fallback* and the built Go app will never use the crypto backend. This is generally not desirable because it can lead to accidental or unclear fallback to Go crypto.
    - The old behavior can be enabled using `GOEXPERIMENT=allowcryptofallback` if necessary, but it is not recommended.
  - Individual crypto calls may still fall back to the Go standard library at runtime if the selected backend doesn't support an API or the arguments used. See the [FIPS User Guide](UserGuide.md) for more information. (This behavior is unaffected by this change.)
- Adds [`systemcrypto` experiment](#usage-build).
- Adds [`requirefips` build tag](#build-option-to-require-fips-mode).

### Go 1.20.6 and 1.19.11 (Jul 2023)

- When multiple versions of OpenSSL are present on the machine at runtime, a version with FIPS mode enabled now has higher priority than others. [microsoft/go-crypto-openssl@v0.2.8](https://github.com/microsoft/go-crypto-openssl/releases/tag/v0.2.8)

### Go 1.19 (Aug 2022)

- CNG (Windows) backend introduced.
- `GOEXPERIMENT` environment variable is now used to select the backend.
  - Upstream Go made this change for BoringCrypto, and we adopted it for our OpenSSL and CNG backends. See [the `dev.boringcrypto` branch readme](https://github.com/golang/go/blob/dev.boringcrypto/README.boringcrypto.md). For more details about the merge, see [golang/go#51940](https://github.com/golang/go/issues/51940). `dev.boringcrypto*` branches are no longer maintained.
  - Downloading a different toolset build to build FIPS vs. non-FIPS programs is no longer necessary.
- Backend selection is done at compile time. The backend is always used by the resulting program, and it can't be changed at runtime.
- Only one Microsoft build of Go is provided per platform. It supports building both FIPS and non-FIPS programs.

### Go 1.16 (Feb 2022)

- OpenSSL (Linux) backend introduced.
- Introduction of FIPS features in the Microsoft build of Go based on the upstream `dev.boringcrypto*` branches of Go.
- The backend is only used if FIPS mode is requested (e.g. `GOFIPS=1`), otherwise the Microsoft build of Go falls back to the Go standard library at runtime.
- To build a FIPS-compliant program, a FIPS-specific toolset build must be downloaded and used.
- For historical information about Go 1.16-1.18, see [the FIPS documentation in the 1.20 release branch](https://github.com/microsoft/go/tree/microsoft/release-branch.go1.20/eng/doc/fips). It includes details about FIPS in 1.18 and the changes in 1.19.

[go-crypto-openssl]: https://github.com/microsoft/go-crypto-openssl
[golang-fips/openssl]: https://github.com/golang-fips/openssl
[go-crypto-winnative]: https://github.com/microsoft/go-crypto-winnative
[go-crypto-darwin]: https://github.com/microsoft/go-crypto-darwin
[dlopen]: https://man7.org/linux/man-pages/man3/dlopen.3.html
[microsoft-go-download]: https://github.com/microsoft/go#binary-distribution
[microsoft-go-images]: https://github.com/microsoft/go-images
[OpenSSL features]: https://github.com/openssl/openssl/blob/4114964865435edc475c9ba49a7fa2b78956ab76/INSTALL.md#enable-and-disable-features
[Azure Linux]: https://github.com/microsoft/azurelinux
[msc10010]: https://liquid.microsoft.com/Web/Object/Read/MS.Security/Requirements/Microsoft.Security.Cryptography.10010
