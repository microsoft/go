This directory contains documentation about FIPS and the FIPS implementation in the Microsoft fork of Go.

* README.md (this file): a general overview and first steps.
* [**FIPS 140 User Guide** (UserGuide.md)](UserGuide.md): notes on FIPS compliance of specific crypto APIs.

# Crypto FIPS 140 support

## Background

FIPS 140 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance and specifically FIPS 140-3 certification may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

The upstream plan to support building FIPS compliant Go apps is described in [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140) and [crypto: obtain a FIPS 140-3 validation (golang/go#69536)](https://github.com/golang/go/issues/69536).
Go 1.24 delivered some major steps in this plan: the crypto module itself (written in Go and Go assembly), the concept of FIPS mode in the Go runtime, and new toolset settings.

Prior to Go 1.24, Google maintained the [goexperiment](https://pkg.go.dev/internal/goexperiment) `boringcrypto`, that uses cgo and BoringSSL to implement various crypto primitives.
As BoringSSL is FIPS 140 certified, an application built using this flag is more likely to be FIPS 140 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140 standard.

In addition to that, the `boringcrypto` flag also provides a mechanism to restrict all TLS configuration to FIPS-compliant settings.
The effect is triggered by importing the fipsonly package anywhere in a program, as in:

```go
  import _ "crypto/tls/fipsonly"
```

In Go 1.24, the TLS FIPS-compliant mode is controlled by the Go runtime's FIPS mode.

## Microsoft build of Go FIPS compliance

The Microsoft build of Go modifies the Go runtime to call into a platform-provided cryptographic library to implement crypto primitives rather than use the standard Go crypto implementations.
Depending on the platform, this is done using cgo or syscalls.
This allows Go programs to use a platform-provided FIPS 140 certified crypto library.

On Linux, the fork uses [OpenSSL](https://www.openssl.org/) through the [golang-fips/openssl] module in Go 1.21+ and the [go-crypto-openssl] module in earlier versions. On Windows, [CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/about-cng), using [go-crypto-winnative]. Since 1.24, on macOS, [CommonCrypto](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/Common%20Crypto.3cc.html) and [CryptoKit](https://developer.apple.com/documentation/cryptokit) using [go-crypto-darwin]. Similar to BoringSSL, certain OpenSSL, CNG and CommonCrypto/CryptoKit versions are FIPS 140 certified.

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
  - [`GOFIPS140=latest` environment variable](#build-option-to-require-fips-mode) (go1.24+)
  - [`import _ "crypto/tls/fipsonly"` source change](#tls-with-fips-compliant-settings)
- Runtime configuration:
  - [`GOFIPS` environment variable](#usage-runtime)
  - [`GODEBUG=fips140` setting](#usage-runtime) (go1.24+)
  - (OpenSSL backend) [`GO_OPENSSL_VERSION_OVERRIDE` environment variable](#runtime-openssl-version-override)
  - (OpenSSL backend) [`/proc/sys/crypto/fips_enabled` file containing `1`](#linux-fips-mode-openssl)
  - (CNG backend) [Windows registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` dword value `Enabled` set to `1`](#windows-fips-mode-cng)

## Usage: Common configurations

There are typically two goals that lead to this document. Creating a FIPS compliant app is one. The other is to comply with internal Microsoft crypto policies that have been set for Go. This table summarizes common configurations and how suitable each one is for these goals.

> [!NOTE]
> This section assumes the use of the Microsoft build of Go 1.24 or later.
>
> 1.24 introduces `GODEBUG=fips140=on` as the preferred way to enable FIPS mode. See also [the Go 1.24 changelog](#go-124-feb-2025).

| Build-time config | Runtime config | Internal Microsoft crypto policy | FIPS behavior |
| --- | --- | --- | --- |
| Default | Default | Not compliant | Crypto usage is not FIPS compliant. |
| `GOEXPERIMENT=systemcrypto` | Default | Compliant | Can be used to create a compliant app. FIPS mode is determined by system-wide configuration. Make sure you are familiar with your platform's system-wide FIPS switch, described in [Usage: Runtime](#usage-runtime). |
| `GOEXPERIMENT=systemcrypto` | `GODEBUG=fips140=on` or `GOFIPS=1` | Compliant | Can be used to create a compliant app. Depending on platform, the app enables FIPS mode, ensures it is already enabled, or doesn't do any additional checks. The app panics if there is a problem. See [Usage: Runtime](#usage-runtime). |
| `GOEXPERIMENT=systemcrypto` | `GO_OPENSSL_VERSION_OVERRIDE=1.1.1k-fips` | Compliant | Can be used to create a compliant app. If the app is built for Linux, `systemcrypto` chooses `opensslcrypto`, and the environment variable causes it to load `libcrypto.so.1.1.1k-fips` instead of using the automatic search behavior. This environment variable has no effect with `cngcrypto`. |
| `GOEXPERIMENT=systemcrypto` and `-tags=requirefips` | Default | Compliant | Can be used to create a compliant app. The behavior is the same as `GODEBUG=fips140=on` and `GOFIPS=1`, but no runtime configuration is necessary. See [the `requirefips` section](#build-option-to-require-fips-mode) for more information on when this "locked-in" approach may be useful rather than the flexible approach. |

A [Docker base image](#dockerfile-base-image) is available that includes suitable build-time config in the environment.

Some configurations are invalid and intentionally result in a build error or runtime panic:

| Build-time config | Runtime config | Behavior |
| --- | --- | --- |
| `-tags=requirefips` | | The build fails. A crypto backend must be specified to enable FIPS features. |
| `GOEXPERIMENT=cngcrypto,opensslcrypto` | | The build fails. Only one crypto backend can be enabled at a time. |
| `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto` | | The build fails. Cgo is required to use the OpenSSL backend. <br/> Prior to Go 1.21 the build would succeed but use standard Go crypto, making the app non-compliant. |

## Usage: Build

The `GOEXPERIMENT` environment variable is used at build time to select a cryptographic library backend. This modifies the Go runtime included in the program to use the specified platform-provided cryptographic library whenever it calls a Go standard library crypto API. The `GOEXPERIMENT` values that pick a crypto backend are:

- *Recommended:* `systemcrypto` automatically selects the suggested crypto backend for the target platform
  - Prior to Go 1.21, this alias is not available and the backend must be selected manually
- `opensslcrypto` selects OpenSSL, for Linux
- `cngcrypto` selects CNG, for Windows
- Since 1.24, `darwincrypto` selects CommonCrypto & CryptoKit for macOS
- `boringcrypto` selects the upstream BoringCrypto backend, which is **not supported and not compliant with internal Microsoft policy**
- If no option is selected, Go standard library cryptography is used.

The options are exclusive and must not be enabled at the same time as one another.

`systemcrypto` matches the internal Microsoft crypto policy for Go. If no compliant backend exists matching the target platform, the build fails.

| Target platform | `systemcrypto` selection | Library |
| --- | --- | --- |
| Linux | `opensslcrypto` | OpenSSL |
| Windows (amd64 and arm64) | `cngcrypto` | CNG |
| macOS (since 1.24) | `darwincrypto` | CommonCrypto & CryptoKit |
| macOS (prior to 1.24) | N/A, build error | N/A |

The crypto backend selection must match the target platform. In a cross-build scenario, such as using Linux to build an app that will run on Windows, `GOOS=windows GOEXPERIMENT=systemcrypto` will correctly select `cngcrypto`.

The Microsoft build of Go must be used for these `GOEXPERIMENT` values to work. See setup instructions in [the distribution section of the microsoft/go readme][microsoft-go-download].

> [!NOTE]
> "Experiment" doesn't indicate the FIPS features are experimental. The original intent of `GOEXPERIMENT` is to use it to enable experimental features in the Go runtime and toolchain, but we and Google are now using `GOEXPERIMENT` for this FIPS-related feature because the mechanism itself perfectly fits our needs.

Setting the `goexperiment.<option>` build tag can be used as an alternative to setting the `GOEXPERIMENT` environment variable.

> [!NOTE]
> For details about combining multiple `GOEXPERIMENT`s and using build tags to customize your build, see [Usage: GOEXPERIMENTs and backend build tags](#usage-goexperiments-and-backend-build-tags).

If a crypto backend is selected but isn't supported, the build fails.
For example, attempting to use the OpenSSL backend without cgo enabled results in a build error.

The next sections describe how to select a crypto backend in some common scenarios.

### Dockerfile base image

If you use a Dockerfile, you can swap its base image to the special Microsoft build of Go images marked with `-fips-`.
These images include `env GOEXPERIMENT=systemcrypto` and are otherwise the same as the non`-fips-` images.
They are provided for convenience.
See [the microsoft/go-images documentation][microsoft-go-images] for more information about available images and how to use them.

### Dockerfile env instruction

If you don't use the standard Go base images (e.g. your Dockerfile downloads the Microsoft build of Go manually), you can use an `env` instruction before the build instruction in your Dockerfile:

```dockerfile
env GOEXPERIMENT=systemcrypto
```

### Modify the build command

Another approach that generally works for any build system is to modify the build command or build script. This section lists some helpful snippets to select a backend.

#### Linux/macOS shell (bash) - Set `GOEXPERIMENT` environment variable

- Set the environment variable for all future commands:
  ```sh
  export GOEXPERIMENT=systemcrypto
  go build ./myapp
  go build ./myapp2
  ```
- Or set the environment variable for only one command:
  ```sh
  GOEXPERIMENT=systemcrypto go build ./myapp
  ```

#### PowerShell - Set `GOEXPERIMENT` environment variable

- ```pwsh
  $env:GOEXPERIMENT = "systemcrypto"
  go build ./myapp
  ```

#### Shell independent - Pass `-tags=...` flag to `go build`

- ```
  go build "-tags=goexperiment.systemcrypto" ./myapp
  ```

> [!NOTE]
> Quoting the argument is necessary in some shells (notably PowerShell) to escape "`.`" or "`,`" if present. Quoting isn't required by every shell.

#### Assign `GOFLAGS` environment variable to automatically pass `-tags=...` to `go build`

- Instead of assigning `GOEXPERIMENT` directly, you can assign `GOFLAGS` to pass `-tags` to `go build`. This is useful if you already use `GOFLAGS` for other purposes, or if it would be difficult to modify `GOEXPERIMENT` for some other reason.
- This is generally not necessary, and using the simpler `GOEXPERIMENT` environment variable is recommended.
- Linux/macOS shell:
  ```
  export GOFLAGS='-tags=goexperiment.systemcrypto'
  go build ./myapp
  ```
- PowerShell:
  ```
  $env:GOFLAGS = "-tags=goexperiment.systemcrypto"
  go build ./myapp
  ```

> [!NOTE]
> If `-tags` is specified in `GOFLAGS` and `-tags` is also passed directly to the build command, the value passed to the build command is used and the one in `GOFLAGS` is ignored.

## Usage: Runtime

A program built with `systemcrypto` always uses the system-provided cryptography library for supported crypto APIs. This is the case for `opensslcrypto` (always using OpenSSL), `cngcrypto` (always using CNG) and `darwincrypto` (always using CommonCrypto/CryptoKit). If the platform's crypto library can't be found or loaded, the Go program panics during initialization.

The following sections describe how to enable FIPS mode and the effect of the `GODEBUG=fips140=on` and `GOFIPS=1` settings on each supported platform.

> [!NOTE]
> Since Go 1.24, setting `GOFIPS=1` is equivalent to setting `GODEBUG=fips140=on`.
> The latter is the recommended way to enable FIPS mode.
> If `GODEBUG=fips140=[...]` is set to `on` or `only`, `GOFIPS` has no effect.
>
> Support for the `GOFIPS` environment variable will be removed in Go 1.25.

> [!NOTE]
> The options described in this section have no effect at build time, only runtime. When the Go program starts up, it examines its environment variables and other platform-specific configurations. This is normally the desired behavior. See [`requirefips`](#build-option-to-require-fips-mode) for info about an optional build tag that may affect FIPS mode.

Since Go 1.24, the Go runtime has an independent FIPS mode, and it may be important to distinguish its FIPS mode from the system or crypto engine's FIPS mode.
The most familiar difference is that it changes TLS stack behavior.
The [Go Runtime FIPS mode](#go-runtime-fips-mode) section describes this in more detail.

Go 1.24 also introduces `GODEBUG=fips140=only`.
It acts as `GODEBUG=fips140=on`, but also makes a best effort to panic if a non-FIPS 140-3 compliant algorithm is used.
This setting is partially supported in Go 1.24.

### Linux FIPS mode (OpenSSL)

To set FIPS mode preference on Linux, use one of the following options. The first match in this list wins:

- Explicitly enable it by setting the environment variable `GODEBUG=fips140=on`.
- Explicitly enable it by setting the environment variable `GOFIPS=1`.
- Implicitly enable it by booting the Linux Kernel in FIPS mode.
  - The Linux Kernel's FIPS mode sets the content of `/proc/sys/crypto/fips_enabled` to `1`. The Go runtime reads this file.

If the Go runtime detects a preference to enable FIPS and OpenSSL is not using a FIPS-compliant engine or provider, the program will panic during program initialization. This may be useful to detect and refuse to run with incorrectly configured OpenSSL installations.

If the Go runtime detects a preference to disable FIPS and OpenSSL is using a FIPS-compliant engine or provider, the program will panic during program initialization.

Otherwise, FIPS preference has no effect.

For more information about the standard OpenSSL FIPS behavior, see https://www.openssl.org/docs/fips.html.

> [!WARNING]
> Prior to Go 1.24, setting `GOFIPS` makes the Go runtime attempt to modify the configured FIPS mode.
> This includes disabling FIPS mode if `GOFIPS=0` even if OpenSSL is configured to be in FIPS mode by default.
>
> Since Go 1.24, the Go runtime no longer makes any attempt to modify OpenSSL FIPS mode.

> [!NOTE]
> Prior to Go 1.24, it was possible to test FIPS mode app behavior on a non-FIPS system by setting `GOFIPS=1`.
> This is no longer possible in 1.24, but some mechanisms are provided by OpenSSL and distros to help run this type of test.
>
> For OpenSSL 3, see [`OPENSSL_CONF`](https://docs.openssl.org/3.0/man5/config/) to change to a FIPS crypto provider.
> For Azure Linux, see [`OPENSSL_FORCE_FIPS_MODE=1`](https://github.com/microsoft/azurelinux/blob/bfd36df1487511735dbd5fade66b0b613c89b46a/SPECS/openssl/0009-Add-Kernel-FIPS-mode-flag-support.patch#L34).

### Windows FIPS mode (CNG)

To enable FIPS mode on Windows, [enable the Windows FIPS policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#step-3-enable-the-fips-security-policy).

If the Go runtime detects `GOFIPS=1` or `GODEBUG=fips140=on` and FIPS policy is not enabled, the program will panic during program initialization. This may be useful to detect and refuse to run on incorrectly configured Windows systems. Otherwise, `GODEBUG=fips140` has no effect.

For testing purposes, Windows FIPS policy can be enabled via the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`, dword value `Enabled` set to `1`.

### macOS FIPS mode (CommonCrypto/CryptoKit)

macOS cryptographic primitives are FIPS compliant by default, so there is no need for system-wide nor process-wide configuration.
Refer to the [About Apple security certifications](https://support.apple.com/guide/certifications/about-apple-security-certifications-apc30d0ed034/1/web/1.0) page for more information.

This means that setting `GOFIPS=1` or `GODEBUG=fips140=on` will never cause a panic on macOS.
They are still necessary to instruct Go to run in FIPS mode, as there is no system-provided parameter to do so.

Prior to 1.24, CommonCrypto/CryptoKit is not used by the Microsoft build of Go.

### Go Runtime FIPS mode

Since Go 1.24, the Go runtime has a FIPS mode.
It is enabled by `GODEBUG=fips140=on` (or any equivalent).
It can be checked by calling [crypto/fips140.Enabled](https://pkg.go.dev/crypto/fips140#Enabled).

This mode has many effects described in [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140).
One notable effect is that the Go runtime TLS stack will only use FIPS-compliant settings.

> [!NOTE]
> Prior to Go 1.24, the Microsoft build of Go automatically applies FIPS compliance changes to the Go runtime (including TLS behavior) when FIPS mode is detected, but it doesn't use a documented mechanism.

The mechanisms in the Mirosoft Build of Go for Linux and Windows automatically enable Go runtime FIPS mode when necessary, based on the system-wide FIPS mode.
For example, if a Linux system is in FIPS mode, the fork enables OpenSSL FIPS mode and the Go runtime FIPS mode.
If a Windows system is in FIPS mode, CNG is already in FIPS mode, and the fork enables the Go runtime FIPS mode.

> [!WARNING]
> On macOS, there is no such thing as system-wide FIPS mode.
> That is: there is no universal way to configure a macOS system to indicate that all programs that run on that system should follow FIPS requirements.
> As a result, the Microsoft build of Go has no reliable indicator that the Go runtime FIPS mode should be enabled.
>
> For compatibility reasons, the Microsoft build of Go defaults to not enabling FIPS settings.
> For example, FIPS settings may prevent an application from connecting to a server that doesn't support FIPS-compliant TLS.
>
> To make the TLS stack use FIPS-compliant settings on macOS, `GODEBUG=fips140=on` (or an equivalent) must be set explicitly.

## Usage: Extra configuration options

### Build option to require FIPS mode

FIPS mode preference is normally determined at runtime, but the `GOFIPS140=latest` and `requirefips` options can be used to make a program always require FIPS mode and panic if FIPS mode is not enabled:

- The `requirefips` build tag is available since Go 1.21. See [the "GOFLAGS" example in the build section](#modify-the-build-command).
- The `GOFIPS140=latest` environment variable is available since Go 1.24.

Most programs aren't expected to use these options. Determining FIPS mode at runtime is normal for FIPS compliant applications. This allows the same binary to be deployed to run in both FIPS compliant contexts and non-FIPS contexts, and allows it to be bundled with other binaries that can also run in both contexts. However, it is useful in some cases:

- Dependence on environment variables like `GODEBUG` and `GOFIPS` in any way may be undesirable.
- The program's documentation can state it will always run in FIPS mode without any nuance about environment variables.
- If the program is used by someone unfamiliar with the system they're configuring, the panic will help catch mistakes before they become a problem.

### Build option to use Go crypto if the backend compatibility check fails

When building a Go program that imports a `crypto` package with a crypto backend, the build will check that the build environment and target are compatible with that backend. If not, the build will fail with an error. For example, a common unsupported build configuration is `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=opensslcrypto`. The OpenSSL backend requires cgo, so the build fails:

```
# runtime
..\..\go\src\runtime\backenderr_gen_nofallback_openssl.go:12:2: `
        The goexperiment.opensslcrypto tag is specified, but other tags required to enable that backend were not met.
        Required build tags:
          goexperiment.opensslcrypto && linux && cgo
        Please check your build environment and build command for a reason one or more of these tags weren't specified.
```

We recommend one of these fixes:

- Fix the build environment to allow the crypto backend to be used. (Enable cgo.)
- Remove `GOEXPERIMENT` entirely. This intentionally doesn't comply with the internal Microsoft crypto policy or FIPS, so for builds within Microsoft, this should only be done under a documented exception.


> [!IMPORTANT]
> Individual crypto calls may fall back to standard Go crypto at runtime if the selected backend doesn't support an API or the arguments used. See the [FIPS User Guide](UserGuide.md) for more information.

### Runtime OpenSSL version override

The `opensslcrypto` Go runtime automatically loads the OpenSSL shared library `libcrypto` using [dlopen] when initializing. Therefore, dlopen's shared library search conventions also apply here.

The `libcrypto` shared library file name varies among different platforms, so a best effort is done to find and load the right file:

- The base name is always `libcrypto.so.`
- Well-known version strings are appended to the base name in this order: `3` -> `1.1` -> `11` -> `111` -> `1.0.2` -> `1.0.0`.
- This may find multiple libraries installed on the machine, so to pick one:
  - A matching library with FIPS mode on by default (e.g. set by system configuration) is chosen immediately.
  - If none have FIPS mode on by default, the first match is used.

This algorithm can be overridden by setting the environment variable `GO_OPENSSL_VERSION_OVERRIDE` to the desired version string. For example, `GO_OPENSSL_VERSION_OVERRIDE="1.1.1k-fips"` makes the runtime look for the shared library `libcrypto.so.1.1.1k-fips` before running the checks for well-known versions.

## Usage: GOEXPERIMENTs and backend build tags

### Multiple GOEXPERIMENTS

When choosing a crypto backend using `GOEXPERIMENT`, you can enable other non-crypto experiments simultaneously using a comma separator, e.g. `GOEXPERIMENT=opensslcrypto,loopvar`. Combining other experiments with one crypto backend experiment is supported.

For more information about other Go experiments, read the output of the command `go doc goexperiment.Flags` to see the experiments available in your specific build of the Go toolset, or check [the online goexperiment package doc](https://pkg.go.dev/internal/goexperiment) to see the options for other versions.

### Build tags

Selecting most `GOEXPERIMENT`s can also be done by setting the corresponding `goexperiment.*` build tag. This is supported for all crypto backends.

For example, `go build -tags=goexperiment.systemcrypto` command will enable the same backend as setting `GOEXPERIMENT=systemcrypto` then running the build command.

### Conditional behavior if a crypto backend is enabled

Normally this is not necessary, but a shared package may need to change its implementation when compiled with a crypto backend rather than the ordinary Go backend. For example, the library may need to remove use of cryptographic algorithms that would not be permitted by FIPS, in a way that will still allow the library to function. This is done using [build constraints](https://pkg.go.dev/go/build#hdr-Build_Constraints), also known as build tags.

- `//go:build goexperiment.systemcrypto` conditionally includes the source file if *any* crypto backend is enabled.
- `//go:build !goexperiment.systemcrypto` includes the file if *no* crypto backend is enabled.

The `goexperiment.systemcrypto` tag's behavior is implemented in a patch to the build system in the Microsoft build of Go.
It is not available in builds of upstream Go.
The constraint `//go:build !goexperiment.systemcrypto` won't cause a build to fail with upstream Go, but it is always satisfied even if the BoringCrypto backend is enabled.
The constraint also doesn't interact with the FIPS features introduced in Go 1.24.

## Features

### No code changes required

The steps above don't require any changes to the app's source code. These steps change the Go runtime, but the crypto APIs are the same. The Go runtime will then favor OpenSSL/CNG crypto primitives over the Go standard library implementation.

Note that while using a FIPS-certified cryptographic module is a FIPS requirement, it is not the only one. Code changes may be needed for a specific app to conform to FIPS in ways that can't be fixed simply by using a modified Go runtime. For example, algorithms and key sizes forbidden by FIPS 140 need to be removed from the app without breaking it. Misuse of approved algorithms must also be fixed. For more information, see the [FIPS User Guide](UserGuide.md).

### Multiple OpenSSL versions allowed

The `opensslcrypto` Go runtime supports multiple OpenSSL versions. It discovers and picks the OpenSSL version to use at runtime, not compile time. This helps make the feature easy to incorporate in existing builds.

Not all OpenSSL versions are supported. OpenSSL does not maintain ABI compatibility between different releases, even if only the patch version is increased, it needs specific attention to implement support. The relative importance of each version also results in a different amount of automated testing that has been implemented for various supported version. These are supported versions and the amount of automated validation for each one:

- OpenSSL 1.1.1: the Microsoft CI builds official releases and runs the Go toolset test suite with this version.
- OpenSSL 1.0.2, 1.1.0, 1.1.1, and 3.0.2: the [golang-fips/openssl] and [go-crypto-openssl] repository CI tests basic operation, but not the integration with the Go runtime.

Versions not listed above are not supported at all.

> [!NOTE]
> Any build of OpenSSL might have various [OpenSSL features] enabled or disabled, diverging from the default configuration. The Microsoft build of Go does not support all possible OpenSSL configurations. Some may cause the Go runtime to panic during initialization or not work as expected.
>
> The Go runtime is tested with the default configuration of each supported OpenSSL version and with the OpenSSL configurations in the [Azure Linux] 2 and [Azure Linux] 3 distributions.

### Dynamic linking

Dynamic linking (as opposed to static linking) is a requirement for an app to be considered FIPS compliant in Microsoft. The approach the modified Go runtime takes meets that requirement.

For OpenSSL, Go uses [dlopen] when initializing. Sometimes this is called *dynamic loading* and not considered part of the *dynamic linking* category (https://stackoverflow.com/a/45959845), but it satisfies requirements for the same reasons as dynamic linking: the OpenSSL library provided by the OS/environment is used, and the app doesn't necessarily have to be rebuilt to take an update.

For CNG, Go uses Windows syscalls to call the CNG APIs. This can also not be considered *dynamic linking*, but like *dynamic loading*, syscalls also mean the app is using OS-provided crypto functionality.

It's common in the Go ecosystem to statically link all dependencies to produce a single binary that can run standalone (e.g. in a minimal Docker container). Unfortunately, the requirements of FIPS and the way it's implemented in Microsoft mean this is not possible for a Go program that uses the Microsoft build of Go runtime and FIPS features. If you are responsible for a Go app in Microsoft and this is impossible, contact the crypto board for more details. We opened an issue to discuss support for static linking: [microsoft/go#744 *OpenSSL static linking proposal*](https://github.com/microsoft/go/issues/744). However, as we learned this would not be considered FIPS compliant for use in Microsoft, we don't have any plans to implement it.

### Portable OpenSSL

The OpenSSL version present when building a program does not have to match the OpenSSL version used when running it. In fact, OpenSSL doesn't need to be present on the builder at all if the built program isn't executed on that system. *Dynamic loading* rather than *linking* makes this possible.

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

### Go 1.25 (Aug 2025)

- Running `go version -m` on a binary which uses a system crypto backend now shows the `microsoft_systemcrypto=1` build setting.

 - The build-time backend compatibility check now only runs when a crypto package is required for the build.
   - If your app doesn't depend on a crypto package, you may, for example, use `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto`.
   - If your app doesn't use a crypto package and you make a change that introduces a crypto package dependency, you will only encounter a compatibility check failure after the change. The change may be in your transitive dependencies: for example, depending on a new module that uses `crypto/sha256` may trigger the compatibility check. This is undesirable, but it's necessary to enable flexibility.

- `GOFIPS=0` support has been removed. It now has no effect.

- `GOEXPERIMENT=allowcryptofallback` has been downgraded to the `allowcryptofallback` build tag. This is an internal mechanism that is not intended for use when building a Go application. This document has always recommended against using it, so we anticipate that this change won't affect users of the Microsoft build of Go. Please [contact the maintainers of the Microsoft build of Go](https://github.com/microsoft/go/blob/microsoft/main/SUPPORT.md) if you need to use it so we can understand the scenario and help find a safer alternative.

### Go 1.24 (Feb 2025)

See the [Microsoft build of Go 1.24 FIPS changes](https://devblogs.microsoft.com/go/go-1-24-fips-update/) blog post for a summary of the Feb 2025 changes.

- Introduces macOS crypto backend `darwincrypto`.
- Support `GODEBUG=fips140=on` as an alias for `GOFIPS=1`.
- `GOFIPS=1` no longer tries to enable FIPS mode on Linux. It will now panic if FIPS mode is not enabled.
- `GOFIPS=0` no longer tries to disable FIPS mode on Linux. It will now panic if FIPS mode is enabled.
- Support for the `GOFIPS` environment variable will be removed in Go 1.25.

### Go [1.22.9-2](https://github.com/microsoft/go/releases/tag/v1.22.9-2) and [1.23.3-2](https://github.com/microsoft/go/releases/tag/v1.23.3-2) (Dec 2024)

- Adds compatibility with changes that [Azure Linux] 3 made to the OpenSSL configuration, specifically the change to use [SCOSSL](https://github.com/microsoft/SymCrypt-OpenSSL). The SCOSSL-related Azure Linux packages must also be up to date for compatibility, at least `SymCrypt-103.6.0-1` and `SymCrypt-OpenSSL-1.6.1-1`.

### Go 1.22 (Feb 2024)

- Automatically enforce that `crypto/tls` and `crypto/x509` only use FIPS-approved settings when running in FIPS mode.

### Go 1.21 (Aug 2023)

- Adds build errors if a crypto backend is selected but not supported.
  - Before 1.21, selecting an unsupported backend causes *silent crypto backend fallback* and the built Go app will never use the crypto backend. This is generally not desirable because it can lead to accidental or unclear fallback to Go crypto.
    - The old behavior can be enabled using `GOEXPERIMENT=allowcryptofallback` if necessary, but it is not recommended.
  - Individual crypto calls may still fall back to the Go standard library at runtime if the selected backend doesn't support an API or the arguments used. See the [FIPS User Guide](UserGuide.md) for more information. (This behavior is unaffected by this change.)
- Adds [`systemcrypto` experiment alias](#usage-build).
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