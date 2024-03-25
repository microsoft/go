This directory contains documentation about FIPS and the FIPS implementation in the Microsoft fork of Go.

* README.md (this file): a general overview and first steps.
* [**FIPS 140-2 User Guide** (UserGuide.md)](UserGuide.md): notes on FIPS compliance of specific crypto APIs.

# Crypto FIPS 140-2 support

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

The Go `crypto` package is not FIPS certified, and the Go team has stated that it won't be, e.g. in [golang/go/issues/21734](https://github.com/golang/go/issues/21734#issuecomment-326980213) Adam Langley says:

> The status of FIPS 140 for Go itself remains "no plans, basically zero chance".

On the other hand, Google maintains the [goexperiment](https://pkg.go.dev/internal/goexperiment) `boringcrypto`, that uses cgo and BoringSSL to implement various crypto primitives. As BoringSSL is FIPS 140-2 certified, an application built using this flag is more likely to be FIPS 140-2 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140-2 standard.

In addition to that, the boringcrypto flag also provides a mechanism to restrict all TLS configuration to FIPS-compliant settings. The effect is triggered by importing the fipsonly package anywhere in a program, as in:

```go
  import _ "crypto/tls/fipsonly"
```

## Microsoft Go fork FIPS compliance

The Microsoft Go fork modifies the Go runtime to implement several crypto primitives using cgo to call into a platform-provided cryptographic library rather than use the standard Go crypto implementations. This allows Go programs to use a platform-provided FIPS 140-2 certified crypto library.

On Linux, the fork uses [OpenSSL](https://www.openssl.org/) through the [golang-fips/openssl] module in Go 1.21+ and the [go-crypto-openssl] module in earlier versions. On Windows, [CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/about-cng), using [go-crypto-winnative]. Similar to BoringSSL, certain OpenSSL and CNG versions are FIPS 140-2 certified.

It is important to note that an application built with Microsoft's Go toolchain and running in FIPS compatible mode is not FIPS compliant _per-se_. It is the responsibility of the application development team to use FIPS-compliant crypto primitives and workflows. The modified crypto runtime will fall back to Go standard library crypto if it cannot provide a FIPS-compliant implementation, e.g. when hashing a message using `crypto/md5` hashes or when using an AES-GCM cipher with a non-standard nonce size.

## Configuration overview

The Microsoft Go fork provides several ways to configure the crypto backend and its behavior. These are described in the following sections in detail.

- Build-time configuration (`go build`):
  - [`GOEXPERIMENT=<backend>crypto` environment variable](#usage-build)
  - [`goexperiment.<backend>crypto` build tag](#usage-build)
  - [`requirefips` build tag](#build-option-to-require-fips-mode)
  - [`GOEXPERIMENT` `allowcryptofallback`](#build-option-to-use-go-crypto-if-the-backend-compatibility-check-fails)
  - [`import _ "crypto/tls/fipsonly"` source change](#tls-with-fips-compliant-settings)
- Runtime configuration:
  - [`GOFIPS` environment variable](#usage-runtime)
  - (OpenSSL backend) [`GO_OPENSSL_VERSION_OVERRIDE` environment variable](#runtime-openssl-version-override)
  - (OpenSSL backend) [`/proc/sys/crypto/fips_enabled` file containing `1`](#linux-fips-mode-openssl)
  - (CNG backend) [Windows registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` dword value `Enabled` set to `1`](#windows-fips-mode-cng)

## Usage: Common configurations

There are typically two goals that lead to this document. Creating a FIPS compliant app is one. The other is to comply with internal Microsoft crypto policies that have been set for Go. This table summarizes common configurations and how suitable each one is for these goals.

> [!NOTE]
> This section assumes the use of Microsoft Go 1.21 or later.
>
> 1.21 introduces `systemcrypto`, `requirefips`, and a build-time compatibility check for the selected crypto backend. The Usage sections go into more detail about the differences between 1.19/1.20 and 1.21 in context. See also [the Go 1.21 changelog](#go-121).

| Build-time config | Runtime config | Internal Microsoft crypto policy | FIPS behavior |
| --- | --- | --- | --- |
| Default | Default | Not compliant | Crypto usage is not FIPS compliant. |
| `GOEXPERIMENT=systemcrypto` | Default | Compliant | Can be used to create a compliant app. FIPS mode is automatically enabled at runtime if it is configured systemwide or `GOFIPS=1`. Flexible. |
| `GOEXPERIMENT=systemcrypto` | `GOFIPS=1` | Compliant | Can be used to create a compliant app. The app either enables FIPS mode or ensures it is already enabled. Otherwise, the app panics. |
| `GOEXPERIMENT=systemcrypto` | `GOFIPS=0` | Compliant | Crypto usage is not FIPS compliant. The app attempts to disable FIPS mode and panics if it isn't possible. |
| `GOEXPERIMENT=systemcrypto` | `GO_OPENSSL_VERSION_OVERRIDE=1.1.1k-fips` | Compliant | Can be used to create a compliant app. If the app is built for Linux, `systemcrypto` chooses `opensslcrypto`, and the environment variable causes it to load `libcrypto.so.1.1.1k-fips` instead of using the automatic search behavior. This environment variable has no effect with `cngcrypto`. |
| `GOEXPERIMENT=systemcrypto` and `-tags=requirefips` | Default | Compliant | Can be used to create a compliant app. The behavior is the same as `GOFIPS=1`, but no runtime configuration is necessary. See [the `requirefips` section](#build-option-to-require-fips-mode) for more information on when this "locked-in" approach may be useful rather than the flexible approach. |

Other notes for common configurations:

- Prior to Go 1.22, if the app uses TLS, `import _ "crypto/tls/fipsonly"` is also necessary for FIPS compliance. See [TLS with FIPS-compliant settings](#tls-with-fips-compliant-settings)
- A Docker image is available that includes suitable build-time config in the environment. See [Dockerfile base image](#dockerfile-base-image)

Some configurations are invalid and intentionally result in a build error or runtime panic:

| Build-time config | Runtime config | Behavior |
| --- | --- | --- |
| `GOEXPERIMENT=systemcrypto` and `-tags=requirefips` | `GOFIPS=0` | The app panics due to the conflict between build-time and runtime configuration. |
| `-tags=requirefips` | | The build fails. A crypto backend must be specified to enable FIPS features. |
| `GOEXPERIMENT=cngcrypto,opensslcrypto` | | The build fails. Only one crypto backend can be enabled at a time. |
| `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto` | | The build fails. Cgo is required to use the OpenSSL backend. <br/> Prior to Go 1.21 or if [`allowcryptofallback`](#build-option-to-use-go-crypto-if-the-backend-compatibility-check-fails) is enabled, the build would succeed but use standard Go crypto, making the app non-compliant. |

## Usage: Build

The `GOEXPERIMENT` environment variable is used at build time to select a cryptographic library backend. This modifies the Go runtime included in the program to use the specified platform-provided cryptographic library whenever it calls a Go standard library crypto API. The `GOEXPERIMENT` values that pick a crypto backend are:

- *Recommended:* `systemcrypto` automatically selects the suggested crypto backend for the target platform
  - Prior to Go 1.21, this alias is not available and the backend must be selected manually
- `opensslcrypto` selects OpenSSL, for Linux
- `cngcrypto` selects CNG, for Windows
- `boringcrypto` selects the upstream BoringCrypto backend, which is **not supported nor compliant**
- If no option is selected, Go standard library cryptography is used.

The options are exclusive and must not be enabled at the same time as one another.

`systemcrypto` matches the internal Microsoft crypto policy for Go. If no compliant backend exists matching the target platform, the build fails.

| Target platform | `systemcrypto` selection | Library |
| --- | --- | --- |
| Linux | `opensslcrypto` | OpenSSL |
| Windows | `cngcrypto` | CNG |
| macOS (not supported: [microsoft/go#1013](https://github.com/microsoft/go/issues/1013)) | N/A, build error | N/A  |

The crypto backend selection must match the target platform. In a cross-build scenario, such as using Linux to build an app that will run on Windows, `GOOS=windows GOEXPERIMENT=systemcrypto` will correctly select `cngcrypto`. Prior to Go 1.21, the selection must be made manually: `GOOS=windows GOEXPERIMENT=cngcrypto`.

Setting the `goexperiment.<option>` build tag can be used as an alternative to setting the `GOEXPERIMENT` environment variable.

> [!NOTE]
> For details about combining multiple `GOEXPERIMENT`s and using build tags to customize your build, see [Usage: GOEXPERIMENTs and backend build tags](#usage-goexperiments-and-backend-build-tags).

If a crypto backend is selected but isn't supported, the build fails. For example, attempting to use the OpenSSL backend without cgo enabled results in a build error.

> [!NOTE]
> Prior to Go 1.21, instead of failing, the build automatically uses the Go standard library crypto implementation. This behavior can cause accidental or unclear fallback to Go crypto, silently breaking compliance with the internal Microsoft crypto policy.
>
> In 1.21, this behavior was changed. Fallback is now opt-in with the `GOEXPERIMENT` `allowcryptofallback`. This option is primarily intended for internal use during the Microsoft Go build and should be avoided in general use. See [`allowcryptofallback`](#build-option-to-allow-go-standard-library-crypto-fallback) for more information.


The Microsoft Go fork must be used for these `GOEXPERIMENT` values to work. See setup instructions in [the distribution section of the microsoft/go readme][microsoft-go-download].

> [!NOTE]
> "Experiment" doesn't indicate the FIPS features are experimental. The original intent of `GOEXPERIMENT` is to use it to enable experimental features in the Go runtime and toolchain, but we and Google are now using `GOEXPERIMENT` for this FIPS-related feature because the mechanism itself perfectly fits our needs.

The next sections describe how to select a crypto backend in some common scenarios.

### Dockerfile base image

Since Go 1.21, you can swap your Dockerfile's base image to the special Microsoft Go images marked with `-fips-`. These images include `env GOEXPERIMENT=systemcrypto` and are otherwise the same as the non`-fips-` images. These exist for convenience. See [the microsoft/go-images documentation][microsoft-go-images] for more information about available images and how to use them.

> [!NOTE]
> Prior to Go 1.21, `-fips-` images do exist, but they are only available for Linux and include `env GOEXPERIMENT=opensslcrypto`. For this reason, these images can't easily be used to build Windows binaries on a Linux host.

### Dockerfile env instruction

If you don't use the standard Go base images (e.g. your Dockerfile downloads Microsoft Go manually), use an `env` instruction before the build instruction in your Dockerfile:

```dockerfile
env GOEXPERIMENT=systemcrypto
```

> [!NOTE]
> Prior to Go 1.21, `systemcrypto` doesn't exist and `opensslcrypto` or `cngcrypto` must be used depending on the target platform.

### Modify the build command

Another approach that generally works for any build system is to modify the build command or build script. This section lists some helpful snippets to select a backend.

> [!NOTE]
> Prior to Go 1.21, `systemcrypto` doesn't exist and `opensslcrypto` or `cngcrypto` must be used depending on the target platform.

#### Linux shell (bash) - Set `GOEXPERIMENT` environment variable

- Set the environment variable for all future commands:
  ```sh
  export GOEXPERIMENT=systemcrypto
  go build ./myapp
  go build ./myapp2
  ```
- Or set the environment variable for only one command:
  ```
  GOEXPERIMENT=systemcrypto go build ./myapp
  ```

#### PowerShell - Set `GOEXPERIMENT` environment variable

- ```pwsh
  $env:GOEXPERIMENT = "cngcrypto"
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
- Linux shell:
  ```
  export GOFLAGS='-tags=goexperiment.systemcrypto'
  go build ./myapp
  ```
- PowerShell:
  ```
  $env:GOFLAGS = "-tags=goexperiment.systemcrypto"
  go build ./myapp
  ```
- Note: if `-tags` is specified in `GOFLAGS` and `-tags` is also passed to the build command, the value passed to the build command is used and the one in `GOFLAGS` is ignored.

## Usage: Runtime

A program built with `opensslcrypto` always uses the OpenSSL library present on the system for crypto APIs. Likewise for `cngcrypto` and CNG. If the platform's crypto library can't be found or loaded, the Go program panics during initialization.

The following sections describe how to enable FIPS mode.

> [!NOTE]
> The options described in this section have no effect at build time, only when the system running the Go program is changed. This is normally the desired behavior. See [`requirefips`](#build-option-to-require-fips-mode) for the optional build tag that enables FIPS mode.

### Linux FIPS mode (OpenSSL)

To set FIPS mode on Linux, use one of the following options. The first match wins:

- Explicitly enable it by setting the environment variable `GOFIPS=1`.
- Explicitly disable it by setting the environment variable `GOFIPS=0`.
- Implicitly enable it by booting the Linux Kernel in FIPS mode.
  - Linux FIPS mode sets the content of `/proc/sys/crypto/fips_enabled` to `1`. The Go runtime reads this file.

If the Go runtime detects a FIPS preference, it configures OpenSSL during program initialization. This includes disabling FIPS mode if `GOFIPS=0`. If configuration fails, program initialization panics.

If no option is detected, the Go runtime doesn't set the OpenSSL FIPS mode, and the standard OpenSSL configuration is left unchanged. For more information about the standard OpenSSL FIPS behavior, see https://www.openssl.org/docs/fips.html.

### Windows FIPS mode (CNG)

To enable FIPS mode on Windows, [enable the Windows FIPS policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#step-3-enable-the-fips-security-policy). For testing purposes, this can be set via the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`, dword value `Enabled` set to `1`.

To make the Go runtime panic during program initialization if FIPS mode is not enabled, set the environment variable `GOFIPS=1`.

> [!NOTE]
> Unlike `opensslcrypto`, a Windows program built with `cngcrypto` doesn't include the ability to enable/disable FIPS, only ensure it's enabled. Windows FIPS mode is not a per-process setting, and changing it may require elevated permissions. Adding this feature would likely have unintended consequences.

## Usage: Extra configuration options

### Build option to require FIPS mode

The `requirefips` feature is available since Go 1.21.

FIPS mode is normally determined at runtime, but the `requirefips` build tag can be used to make a program always require FIPS mode and panic if FIPS mode can't be enabled for any reason.

Most programs aren't expected to use this tag. Determining FIPS mode at runtime is normal for FIPS compliant applications. This allows the same binary to be deployed to run in both FIPS compliant contexts and non-FIPS contexts, and allows it to be bundled with other binaries that can also run in both contexts. However, in some situations, compile-time `requirefips` is desirable:

- Dependence on environment variables like `GOFIPS` in any way may be undesirable.
- The program's documentation can state it will always run in FIPS mode without any nuance about environment variables.
- If the program is used by someone unfamiliar with the system they're configuring, the panic will help catch mistakes before they become a problem.

We chose to make a `requirefips` Go program panic if `GOFIPS=0` rather than silently ignoring the setting. This helps avoid a surprise if a user of a `requirefips` program sets `GOFIPS=0` and expects it to turn off FIPS mode. It may not be obvious which programs are built using `requirefips`, and the panic is intended to help avoid confusion.

Modifying the `go build` command to include `-tags=requirefips` enables this feature. However, if it is difficult to change the build command but possible to change the environment (e.g. by modifying a Dockerfile's `FROM` image), the `GOFLAGS` environment variable can be used to pass `-tags=requirefips` to every `go build` command that runs. See [the "GOFLAGS" example in the build section](#modify-the-build-command).

### Build option to use Go crypto if the backend compatibility check fails

When building a Go program with a crypto backend, the build will check that the build environment and target are compatible with that backend. If not, the build will fail with an error. For example, a common unsupported build configuration is `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=opensslcrypto`. The OpenSSL backend requires cgo, so the build fails:

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

Prior to Go 1.21, if the backend is not compatible with the build environment and target, the assigned backend is completely ignored and the standard Go crypto implementation is used by the built app. This is called *silent crypto backend fallback* and makes the built Go app noncompliant with internal Microsoft crypto policy and FIPS. For backward compatibility and exceptional cases, this behavior can be enabled in Go 1.21 and above using the `allowcryptofallback` experiment.

We recommend against using `allowcryptofallback`. It makes it unclear whether or not the app is intended to be compliant, and could lead to accidental use of Go crypto in a context where FIPS compliance is expected.

> [!IMPORTANT]
> Even if `allowcryptofallback` is not enabled, a Go app may use Go standard library crypto and not be FIPS compliant.
> Individual crypto calls may fall back to standard Go crypto at runtime if the selected backend doesn't support an API or the arguments used. See the [FIPS User Guide](UserGuide.md) for more information.

This table shows an example of the fragile behavior that results from using `allowcryptofallback`:

| Build-time config | Internal Microsoft crypto policy | FIPS behavior |
| --- | --- | --- |
| `GOOS=linux GOEXPERIMENT=systemcrypto,allowcryptofallback` | Compliant | *Not recommended,* but can be used to create a compliant app, as `allowcryptofallback` has no effect in this situation. |
| `GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto,allowcryptofallback` | Not compliant | Crypto usage is not FIPS compliant. `systemcrypto` on `linux` picks the OpenSSL backend. The backend requires cgo, so `CGO_ENABLED=0` would normally result in a build error. However, `allowcryptofallback` causes the Go standard library crypto to be used and ignores the error. |

A scenario we expect is that a dev attempts to rebuild an open source Go app with an OpenSSL backend to start working towards FIPS compliance. A Dockerfile or other build script provided by the open source project may set `CGO_ENABLED=0` in a non-obvious way. With *silent crypto backend fallback*, the dev needs to notice that the OpenSSL backend isn't being used in some situations (e.g. `GOFIPS=1` causes failure) and figure out why. If they don't notice, they may deliver an app that uses Go crypto without realizing it. The compatibility check makes it so this issue blocks the build and can't be missed.

> [!NOTE]
> In rare cases, it may be more practical to use `allowcryptofallback` than to remove the `GOEXPERIMENT`. For example, a generic build script that supports many platforms, some of which don't support crypto backends, may find it practical to use `GOEXPERIMENT=systemcrypto,allowcryptofallback` despite the risk of unclear or accidental fallback to Go crypto.
>
> For example, `allowcryptofallback` plays an important role in the Microsoft Go build process. We have CI jobs that run the build and tests under the OpenSSL, CNG, and Boring crypto backends, but parts of the upstream build and tests disable cgo and run cross-builds. This would cause a failure because the backend can't be enabled, but by including `allowcryptofallback`, the build is allowed to continue and fall back to the Go standard library crypto implementation when necessary.

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

Since Go 1.21:
- `//go:build goexperiment.systemcrypto` conditionally includes the source file if *any* crypto backend is enabled.
- `//go:build !goexperiment.systemcrypto` includes the file if *no* crypto backend is enabled.

> [!NOTE]
> Prior to the introduction of the systemcrypto alias in Go 1.21, the constraint is:  
  `//go:build goexperiment.opensslcrypto && goexperiment.cngcrypto && goexperiment.boringcrypto`.

The `goexperiment.systemcrypto` tag's behavior is implemented in a Microsoft Go patch to the build system. It is not available in builds of upstream Go. The constraint `//go:build !goexperiment.systemcrypto` won't cause a build to fail with upstream Go, but it is always satisfied even if the BoringCrypto backend is enabled.

## Features

### No code changes required

The steps above don't require any changes to the app's source code. These steps change the Go runtime, but the crypto APIs are the same. The Go runtime will then favor OpenSSL/CNG crypto primitives over the Go standard library implementation.

Note that while using a FIPS-certified cryptographic module is a FIPS requirement, it is not the only one. Code changes may be needed for a specific app to conform to FIPS in ways that can't be fixed simply by using a modified Go runtime. For example, algorithms and key sizes forbidden by FIPS 140-2 need to be removed from the app without breaking it. Misuse of approved algorithms must also be fixed. For more information, see the [FIPS User Guide](UserGuide.md).

### Multiple OpenSSL versions allowed

The `opensslcrypto` Go runtime supports multiple OpenSSL versions. It discovers and picks the OpenSSL version to use at runtime, not compile time. This helps make the feature easy to incorporate in existing builds.

Not all OpenSSL versions are supported. OpenSSL does not maintain ABI compatibility between different releases, even if only the patch version is increased, it needs specific attention to implement support. The relative importance of each version also results in a different amount of automated testing that has been implemented for various supported version. These are supported versions and the amount of automated validation for each one:

- OpenSSL 1.1.1: the Microsoft CI builds official releases and runs the Go toolset test suite with this version.
- OpenSSL 1.0.2, 1.1.0, 1.1.1, and 3.0.2: the [golang-fips/openssl] and [go-crypto-openssl] repository CI tests basic operation, but not the integration with the Go runtime.

Versions not listed above are not supported at all.

Note that one can enable or disable certain [OpenSSL features] when building it, diverging from the default configuration. The Go runtime does not support all possible configurations, and some may cause the Go runtime to panic during initialization or not work as expected. The Go runtime is tested with the default configuration of the supported versions and with the OpenSSL configuration shipped in [Azure Linux]. 

### Dynamic linking

Dynamic linking (as opposed to static linking) is a requirement for an app to be considered FIPS compliant in Microsoft. The approach the modified Go runtime takes meets that requirement.

For OpenSSL, Go uses [dlopen] when initializing. Sometimes this is called *dynamic loading* and not considered part of the *dynamic linking* category (https://stackoverflow.com/a/45959845), but it satisfies requirements for the same reasons as dynamic linking: the OpenSSL library provided by the OS/environment is used, and the app doesn't necessarily have to be rebuilt to take an update.

For CNG, Go uses Windows syscalls to call the CNG APIs. This can also not be considered *dynamic linking*, but like *dynamic loading*, syscalls also mean the app is using OS-provided crypto functionality.

It's common in the Go ecosystem to statically link all dependencies to produce a single binary that can run standalone (e.g. in a minimal Docker container). Unfortunately, the requirements of FIPS and the way it's implemented in Microsoft mean this is not possible for a Go program that uses the Microsoft Go runtime and FIPS features. If you are responsible for a Go app in Microsoft and this is impossible, contact the crypto board for more details. We opened an issue to discuss support for static linking: [microsoft/go#744 *OpenSSL static linking proposal*](https://github.com/microsoft/go/issues/744). However, as we learned this would not be considered FIPS compliant for use in Microsoft, we don't have any plans to implement it.

### Portable OpenSSL

The OpenSSL version present when building a program does not have to match the OpenSSL version used when running it. In fact, OpenSSL doesn't need to be present on the builder at all if the built program isn't executed on that system. *Dynamic loading* rather than *linking* makes this possible.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain.

### TLS with FIPS-compliant settings

The Go TLS stack will automatically use crypto primitives from the selected crypto backend. Yet, this isn't enough for FIPS compliance: the FIPS 140-2 standard places additional restrictions on TLS communications, mainly on which cyphers and signers are allowed. Note that this can reduce compatibility with old devices that do not support modern cryptography techniques such as TLS 1.2.

Since Go 1.22, the Microsoft Go runtime automatically enforces that `crypto/tls` and `crypto/x509` only use FIPS-compliant settings when running in FIPS mode. This differs from upstream's BoringCrypto backend, which requires you to import `crypto/tls/fipsonly` to apply the FIPS-mandated restrictions. The Microsoft Go crypto backends do this automatically to reduce the source code changes necessary to produce a FIPS-compliant Go application, and to make it easier to use the same binary in both FIPS and non-FIPS environments.

Prior to Go 1.22, a program using the Go TLS stack must import the `crypto/tls/fipsonly` package to be compliant with these restrictions. The configuration is done by an `init()` function, so only importing it is necessary:

```go
  import _ "crypto/tls/fipsonly"
```

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- All crypto stubs are a mirror of Google's [dev.boringcrypto branch](https://github.com/golang/go/tree/dev.boringcrypto) and the release branch ports of that branch.
- The mapping between BoringSSL and OpenSSL APIs is taken from Fedora's [Go fork](https://pagure.io/go).
- Portable OpenSSL implementation ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Disclaimer

A program running in FIPS mode can claim it is using a FIPS-certified cryptographic module, but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Changelog

This list of major changes is intended for quick reference and for access to historical information about versions that are no longer supported. The behavior of all in-support versions are documented in the sections above with notes for version-specific differences where necessary.

### Go 1.22 (Feb 2023)

- Automatically enforce that `crypto/tls` and `crypto/x509` only use FIPS-approved settings when running in FIPS mode.

### Go 1.21 (Aug 2023)

- Adds build errors if a crypto backend is selected but not supported.
  - Before 1.21, selecting an unsupported backend causes *silent crypto backend fallback* and the built Go app will never use the crypto backend. This is generally not desirable because it can lead to accidental or unclear fallback to Go crypto.
    - The old behavior can be enabled using the [`allowcryptofallback` experiment](#build-option-to-use-go-crypto-if-the-backend-compatibility-check-fails) if necessary, but it is not recommended.
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
- Only one Microsoft Go toolset is provided per platform. It supports building both FIPS and non-FIPS programs.

### Go 1.16 (Feb 2022)

- OpenSSL (Linux) backend introduced.
- Introduction of FIPS features in the Microsoft Go fork based on the upstream `dev.boringcrypto*` branches of Go.
- The backend is only used if FIPS mode is requested (e.g. `GOFIPS=1`), otherwise Microsoft Go falls back to the Go standard library at runtime.
- To build a FIPS-compliant program, a FIPS-specific toolset build must be downloaded and used.
- For historical information about Go 1.16-1.18, see [the FIPS documentation in the 1.20 release branch](https://github.com/microsoft/go/tree/microsoft/release-branch.go1.20/eng/doc/fips). It includes details about FIPS in 1.18 and the changes in 1.19.

[go-crypto-openssl]: https://github.com/microsoft/go-crypto-openssl
[golang-fips/openssl]: https://github.com/golang-fips/openssl
[go-crypto-winnative]: https://github.com/microsoft/go-crypto-winnative
[dlopen]: https://man7.org/linux/man-pages/man3/dlopen.3.html
[microsoft-go-download]: https://github.com/microsoft/go#binary-distribution
[microsoft-go-images]: https://github.com/microsoft/go-images
[OpenSSL features]: https://github.com/openssl/openssl/blob/4114964865435edc475c9ba49a7fa2b78956ab76/INSTALL.md#enable-and-disable-features
[Azure Linux]: https://github.com/microsoft/azurelinux