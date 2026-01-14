# Migration Guide: Microsoft build of Go

This guide provides high-level guidance to help migrate from the [official Go distribution](https://go.dev/) to the [Microsoft build of Go](https://github.com/microsoft/go), comply with Microsoft internal cryptography policy, and (in some cases) build a FIPS compliant Go program.
It's intended for developers who work on a Go project at Microsoft.

The Microsoft build of Go is designed to be a drop-in replacement for official Go.
It's a fork, and some runtime behavior slightly differs, but in most cases it has full compatibility with ordinary Go projects.
We expect that most projects don't require any Go code changes to work with the Microsoft build of Go.

Note that the Microsoft build of Go has [toolset telemetry enabled by default](https://devblogs.microsoft.com/go/microsoft-go-telemetry/) (opt-out telemetry).
See [the Data Collection policy for the Microsoft build of Go](/README.md#data-collection).

## Quick start

To comply with Microsoft internal policy for the use of Go, most projects need to:

1. [Use the Microsoft build of Go **for CI (Continuous Integration) and build environments.**](#ci-and-build-environment-migration-steps)
    - See [Microsoft Toolset Identification](./MicrosoftToolsetIdentification.md) if it's not clear which distribution of Go you're currently using.
1. If you use a version of Go prior to 1.25, [enable `systemcrypto`](#enable-systemcrypto).
    - Starting with 1.25 (Linux and Windows) and 1.26 (macOS), `systemcrypto` is enabled by default, and no action is required.
1. [**Test** your program.](#testing)
    - It's important to test on all target platforms. The changes to runtime behavior are platform-specific.
1. Consider **whether your project must be FIPS compliant** and if so, [**review your project**](#review-project-for-fips-compliance).
    - For example, FedRAMP approval generally requires FIPS compliance.
    - Using `systemcrypto` is not sufficient to claim FIPS compliance. A specific review is necessary.

For local development, it's not required to use the Microsoft build of Go.
Consider [installing the toolset](/README.md#download-and-install) on a developer machine if you need to use it to debug behavior that's specific to the Microsoft build.

Like the official Go distribution, the Microsoft build of Go has no Go runtime component that must be installed in the target environment.
Your Go application is still a single executable binary.
However, in some cases, it may now have additional dependencies.

Regardless of which method you use to install Go, we recommend picking a specific major version of Go and setting up your build system to use the latest update to that major version, a.k.a. pinning the major version.
Both official Go and the Microsoft build of Go occasionally have breaking changes in new major versions, and pinning lets you plan for and execute migrations at your own pace.
However, we recognize that pinning increases maintenance burden when there are no breaking changes, and ultimately the risk must be evaluated in the context of each project.

## What's different?

The Microsoft build of Go includes [patches](/patches/) that:

- **Integrate `crypto` packages with system-provided cryptographic engines** on Linux, Windows and macOS.
- **Enable FIPS compliance** in a way compatible with Microsoft internal crypto policy: using system-provided engines.
- **Enhance FIPS mode runtime behavior** for scenarios we have encountered in Microsoft's and others' Go applications.
- **Add [toolset telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/)**, enabled by default.
- **Disable [GOTOOLCHAIN](https://go.dev/doc/toolchain) by default** to avoid mixups with the official Go distribution.
- **Remove use of undocumented Windows APIs** for compatibility, security, and compliance.

The patches directory at each Git tag specifies the exact code changes we have made to the official Go toolchain of that version.
If it's critical to you to understand the exact set of changes we've made, please review the patch files.

## CI and build environment migration steps

This section describes some migration scenarios we know about and the path we recommend following for each one.

> [!NOTE]
> Any method of installing the Microsoft build of Go specified [in the project README file](/README.md#download-and-install) is valid.
> If you see a good fit, go ahead and use it.
>
> The scenarios in the following sections simply offer targeted guidance to help find the easiest approach.

### The `GoTool@0` Azure Pipelines step

The `GoTool@0` step doesn't currently support the Microsoft build of Go, and there is no equivalent step.
(See [microsoft/go#483](https://github.com/microsoft/go/issues/483).)

The most universal replacement is to use a `script` step to run [the cross-platform `go-install.ps1` script](/README.md#the-go-installps1-script).

### A `go` toolset that happens to be on my build agent

Some build agents (VMs, containers, etc.) have `go` conveniently pre-installed, but it's the official distribution of Go rather than the Microsoft build.
A universal migration is to use [the cross-platform `go-install.ps1` script](/README.md#the-go-installps1-script).
However, we recommend looking at these options first:

* Request that your agent provider includes the Microsoft build of Go.
* Pick a different agent.
* Run a [container job that uses Microsoft build of Go container image](#an-azure-pipelines-container-job-referring-to-the-official-golang-container-image).

### An Azure Pipelines container job referring to the official `golang` container image

If you use [container jobs](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/container-phases?view=azure-devops&tabs=linux) with the official Go container images on Dockerhub (or a mirror), swap the image to a Microsoft build of Go container image hosted on MAR (Microsoft Artifact Registry).

You may be able to simply prepend `mcr.microsoft.com/oss/go/microsoft/` to your tag reference.

See the [Microsoft build of Go container image documentation](https://github.com/microsoft/go-images/blob/microsoft/main/README.md) for more information about available container images.

### A Dockerfile based on the official `golang` image

You may be able to simply prepend `mcr.microsoft.com/oss/go/microsoft/` to your `BASE` tag reference.
See the [Microsoft build of Go container image documentation](https://github.com/microsoft/go-images/blob/microsoft/main/README.md) for more information about available container images.

> [!Note]
> Make sure to [use a multi-stage Dockerfile](https://docs.docker.com/build/building/multi-stage/) so you don't deploy all build dependencies to production.
> The Microsoft build of Go's container images are designed to be used for the build stage, not the final, deployment, stage.

### The Azure Linux 3 `golang` package

The `golang` package in the Azure Linux 3 Linux distribution is the Microsoft build of Go.
If you're using it, no action is needed.

### An Ubuntu `golang` package

Ubuntu packages for the Microsoft build of Go are `msft-golang` on the [Linux Software Repository for Microsoft Products](https://learn.microsoft.com/en-us/linux/packages), also known as PMC (packages.microsoft.com).
Install instructions [are in the project README file](/README.md#ubuntu).

### A OneBranch Azure Pipeline

We are not aware of an enhanced migration path for OneBranch pipelines that should be preferred over the Azure Pipelines migrations mentioned above.
See the above sections for [`GoTool@0`](#the-gotool0-azure-pipelines-step) and [container jobs](#an-azure-pipelines-container-job-referring-to-the-official-golang-container-image) to find the best fit for your project.

### Direct download of the Go `tar.gz` or `zip` file

If you currently download an archived binary release of Go directly, you can switch to [Microsoft build of Go binary archives](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/Downloads.md).
That page provides links that redirect to the latest version and also immutable links to specific releases.

## Enable `systemcrypto`

These instructions are for projects using versions of Go that don't enable `systemcrypto` by default.
Starting with 1.25 (Linux and Windows) and 1.26 (macOS), `systemcrypto` is enabled by default.

To comply with Microsoft internal cryptography policy, enable the `systemcrypto` feature in your build environment before building your project.
This is done by setting the `GOEXPERIMENT` environment variable to `systemcrypto`.

See [the FIPS documentation sections about build configuration](fips/README.md#usage-common-configurations) for more detailed instructions.
Even if you don't need FIPS compliance, the `GOEXPERIMENT` instructions are located in that document.

## Testing

Make sure pipelines that run `go test` also use the Microsoft build of Go.
It's important that tests exercise the same runtime behavior as a build that is eventually deployed or shipped.

We recommend that in addition to your normal tests, you [examine your final binary](./MicrosoftToolsetIdentification.md#examining-go-binaries) to confirm that it was built with the Microsoft build of Go.

### Common build issues

After switching to the Microsoft build of Go, you may encounter new build errors.

#### Cgo is not enabled

```
Using GOEXPERIMENT=systemcrypto on Linux requires CGO_ENABLED=1.

Consider using our CGO-less experiement by setting GOEXPERIMENT=ms_nocgo_opensslcrypto.
	
For more information, visit https://github.com/microsoft/go/blob/microsoft/main/eng/doc/MigrationGuide.md#cgo-is-not-enabled
```

> [!NOTE]
> As of Go 1.26, there is a CGO-less experiment available for Linux: `ms_nocgo_opensslcrypto`.
> This will allow use of OpenSSL without requiring cgo.

When targeting Linux, `systemcrypto` requires cgo.
Cgo is disabled by default on some platforms or when a C compiler is not detected
Sometimes a project's build scripts might explicitly disable cgo.
There are good reasons to disable cgo, but unfortunately, cgo is currently necessary to use `systemcrypto` on Linux.

In this case, you should first try to install a C compiler, like `gcc`.

You may also need to set the `CGO_ENABLED` environment variable to `1` or [otherwise enable cgo](https://pkg.go.dev/cmd/cgo).

If this isn't feasible, see [disabling systemcrypto](#disabling-systemcrypto).

#### Missing C toolchain and dependencies

A C toolchain is required to build programs that use `systemcrypto` on Linux.
The errors shown with a partially missing C toolchain can be unintuitive, so some errors and corresponding missing packages with the names they have on Azure Linux 3 are listed below.

```
# runtime/cgo
cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in $PATH
```

`gcc`

```
_cgo_export.c:3:10: fatal error: stdlib.h: No such file or directory
    3 | #include <stdlib.h>
      |          ^~~~~~~~~~
```

`glibc-devel`

```
gcc: fatal error: cannot execute ‘as’: execvp: No such file or directory
```

`binutils`

```
In file included from /usr/include/errno.h:28,
                 from cgo-gcc-prolog:32:
/usr/include/bits/errno.h:26:11: fatal error: linux/errno.h: No such file or directory
   26 | # include <linux/errno.h>
      |           ^~~~~~~~~~~~~~~
```

`kernel-headers`

If you're using Azure Linux 3, you can run this command to make sure all required C toolchain packages are installed:

```bash
sudo tdnf install gcc glibc-devel binutils kernel-headers
```

Alternatively, the `build-essential` package contains all of these packages and more.

If this isn't feasible, see [disabling systemcrypto](#disabling-systemcrypto).

#### Unknown GOEXPERIMENT systemcrypto

```
go: unknown GOEXPERIMENT systemcrypto
```

```
go.exe: unknown GOEXPERIMENT systemcrypto
```

This error indicates you aren't using the Microsoft build of Go.
It happens when the `GOEXPERIMENT` environment variable includes `systemcrypto` (or `nosystemcrypto`) and the Go toolset doesn't recognize it.

If you're trying to migrate to the Microsoft build of Go, check your build environment to ensure that the `go` command is the Microsoft build of Go.
See [Microsoft Toolset Identification](./MicrosoftToolsetIdentification.md).

If you're trying to make a build command compliant with Microsoft crypto policy but still compatible with **both the Microsoft build of Go and the official Go distribution**, this is possible:

- If you're using Go 1.25 or later, remove `systemcrypto` from `GOEXPERIMENT`. Starting in 1.25, `systemcrypto` is enabled by default.
  - If `GOEXPERIMENT` only contains `systemcrypto`, delete the assignment entirely.
  - If it's not possible to find the `GOEXPERIMENT` setting in your build scripts and remove `systemcrypto`, reassign `GOEXPERIMENT` to remove `systemcrypto` just before your build commands.
- If you're using Go 1.24 or earlier, or want to use both 1.24 and 1.25, use build tags instead of `GOEXPERIMENT`.
  - Manually enabling `systemcrypto` in the Microsoft build of Go 1.25 is unnecessary, but harmless.

**Build tags** (also known as build constraints) are more flexible than `GOEXPERIMENT`: build tag names are not verified against the list of known experiments.
You can pass build tags to a `go build` command using the `-tags` flag:

```
go build -tags=goexperiment.systemcrypto .
```

See [Build Tags](fips/README.md#build-tags) in the FIPS README documentation for more information about using build tags with `systemcrypto`.

If passing additional arguments to `go build` is undesirable, you can alternatively set up the `GOFLAGS` environment variable to include `-tags=goexperiment.systemcrypto`.
This makes all subsequent `go` commands automatically use that build tag.
See [`cmd/go` documentation](https://pkg.go.dev/cmd/go#hdr-Environment_variables) and [the FIPS readme](fips/README.md#assign-goflags-environment-variable-to-automatically-pass--tags-to-go-build) for more information about using GOFLAGS.

> [!WARNING]
> `nosystemcrypto` can't be specified as a build tag.

See [Disabling `systemcrypto`](#disabling-systemcrypto) for information about how to disable `systemcrypto` if you need to temporarily avoid migrating to it.

### Common test or runtime issues

#### Missing OpenSSL or SymCrypt dependencies

```
panic: opensslcrypto: can't initialize OpenSSL libcrypto.so: openssl: can't load libcrypto.so: libcrypto.so: cannot open shared object file: No such file or directory
```

You may be missing a required runtime dependency.
Required OpenSSL packages on Azure Linux 3 are:

- `openssl`
- `symcrypt` `>=` 103.6.0-1
- `symcrypt-openssl` (SCOSSL) `>=` 1.6.1-1

You may need to run `tdnf install -y openssl symcrypt symcrypt-openssl`.
Otherwise, identify why these packages are not present.

If your system has a `libcrypto.so[...]` file that doesn't follow [the expected naming conventions, you can set the `GO_OPENSSL_VERSION_OVERRIDE` environment variable](fips/README.md#runtime-openssl-version-override) to make your Go program look for a specific suffix.

If this isn't feasible, see [disabling systemcrypto](#disabling-systemcrypto).

#### FIPS mode requested but not available

```
panic: opensslcrypto: FIPS mode requested (environment variable GODEBUG=fips140=on) but not available: OpenSSL 3.3.3 11 Feb 2025
```

```
panic: opensslcrypto: FIPS mode requested (requirefips tag set) but not available: OpenSSL 3.3.3 11 Feb 2025
```

```
panic: opensslcrypto: FIPS mode requested (system FIPS mode) but not available: OpenSSL 3.3.3 11 Feb 2025
```

These error messages indicate that the program is attempting to run in FIPS mode, but FIPS mode isn't available on the current system.
The message in parentheses indicates why the Go program has requested FIPS mode.

On Azure Linux 3, this may be caused by [missing OpenSSL or SymCrypt dependencies](#missing-openssl-or-symcrypt-dependencies).

#### Performance seems significantly worse

We expect performance to be comparable to standard Go.
Some patterns of using `crypto` may be more particularly impacted than others.

Please [contact us](/SUPPORT.md) for help with specific performance problems.

#### Long path errors on Windows

Removing the use of undocumented Windows APIs unfortunately removed a feature that allows long paths to work by default for Go programs.
Long paths do work in many scenarios, because the Go standard library uses the `\\?\` prefix when possible.
However, some use of long paths, in particular outside of the `os` package, may fail.

See [the upstream proposal golang/go#66560](https://github.com/golang/go/issues/66560) for more information on this limitation and why the official Go distribution uses the undocumented API.

Application code and libraries that use Windows paths may need to be updated to [use the `\\?\` prefix to exceed the long path limit](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-file-namespaces).

#### glibc resolution failure on Linux

```
./app: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./app)
./app: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./app)
```

When building a program with cgo on Linux (required when using `systemcrypto`), the system's glibc version is linked into the binary.
When the program runs on a different system with an older version of glibc, it may fail to start with an error like the above.

There are several approaches to resolve this problem:

- **Always build on the same platform as the target system.** This may be feasible for services, but it makes shipping an application that can run on a variety of Linux systems difficult to manage.
- **Build on the oldest possible Linux distribution.** This is a common approach, and often works well. However, it may pose a challenge for maintenance, because you need to keep an older system available for builds, and the upgrade window is narrow: you need to upgrade to avoid Linux distro EOL, but not too far in advance to break your compatibility goal.
- **Use a rootfs that links against an old version of glibc.** This is very effective and also allows cross-compilation, but it requires more complicated setup.
    - For more information about how to implement this approach, see [microsoft/go#1866](https://github.com/microsoft/go/issues/1866).

On Alpine Linux, `glibc` isn't present at all.
It uses `musl` instead of `glibc`.
Try installing the `gcompat` or `libc6-compat` Alpine packages to use a `glibc` compatibility layer.
Gathering more information about behavior on Alpine is tracked by [microsoft/go#1867](https://github.com/microsoft/go/issues/1867).

If this isn't feasible, see [disabling systemcrypto](#disabling-systemcrypto).

#### Cryptography package failures while in FIPS mode

While in FIPS mode:

- Some crypto algorithms may be restricted.
- TLS connections use FIPS-approved ciphers only.
- Some legacy crypto operations may not be available.

If you encounter an unexpected failure while using a `crypto` package, find the function in the [FIPS User Guide](fips/UserGuide.md) to see any known limitations.
A summary of compatible algorithms for each supported platform can be found at [Cross-Platform Cryptography in the Microsoft build of Go](CrossPlatformCryptography.md).

## Review project for FIPS compliance

If your project targets FIPS compliance, you need to do additional manual validation to ensure your project meets FIPS requirements.
These resources may help:

- Read the [FIPS Overview](fips/README.md) for background and additional build and runtime configuration
- See [CrossPlatformCryptography.md](CrossPlatformCryptography.md) for an overview of supported algorithms on various platforms.
- Review the [FIPS User Guide](fips/UserGuide.md) for deep API-specific guidance

For specific guidance within Microsoft:

- Read [Microsoft.Security.Cryptography.10010 on the Liquid Microsoft-internal site.][msc10010]
- Contact the crypto board

## Disabling `systemcrypto`

The difficulty of migrating to using `systemcrypto` can vary significantly depending on the Go project.
If the change requires further planning and if it's acceptable for your project to be temporarily out of compliance with Microsoft cryptography policy, you can disable `systemcrypto` by following these instructions:

- If you're using Go 1.25.2 or later, set the `MS_GO_NOSYSTEMCRYPTO` environment variable to 1.
- Otherwise, set the `GOEXPERIMENT` environment variable to `nosystemcrypto`.
  - If you have already set `GOEXPERIMENT`, append `,nosystemcrypto` to the existing value.

After that, build commands won't encounter errors related to `systemcrypto`, and the resulting program won't attempt to use system-provided cryptography at runtime.

For more information about these options, see [the "Build option to use Go crypto" section of the FIPS README](fips/README.md#build-option-to-use-go-crypto-if-the-backend-compatibility-check-fails).

Alternatively, if you experienced an unexpected auto-update to 1.25 that broke your project, you should downgrade to the latest version of 1.24.
This will disable `systemcrypto` by default and give you time to plan the migration.
You can choose to upgrade at your own pace, as long as you complete the migration before 1.24 reaches EOL (End of Life).
**1.24 EOL is expected in February 2025.**

For most installation methods, specify 1.24, and you will get the latest, most secure version of 1.24.

> [!TIP]
> To update to the latest version of 1.24 in Azure Linux 3, use this command:
>
> ```bash
> sudo tdnf install -y 'golang < 1.25'
> ```
>
> Using the constraint `< 1.25` rather than a specific version ensures that you get the latest, most secure version of Go 1.24.
>
> Some care may be needed: the above command installs, downgrades, or updates `golang`, but it doesn't lock the version to 1.24.
> `golang` will be updated to the latest version of 1.25 the next time you run `tdnf update`.
> This command may only be suitable for some situations, such as CI, and may need to be run just before any steps that use `go`.
>
> `dnf` has `versionlock` capabilities, but it doesn't enable upgrades to newer patches within the major version.
> It will only lock to a specific version.

If you're unable to complete migration to `systemcrypto` right away, we recommend disabling systemcrypto with 1.25 rather than using 1.24, if possible.
This approach lets you benefit from other changes in 1.25.
It also avoids setting the migration deadline of 1.24 EOL.

More information about exceptions to the Microsoft cryptography policy can be found at [Microsoft.Security.Cryptography.10010 on the Liquid Microsoft-internal site.][msc10010]

> [!NOTE]
> Like any major version of Go, there may be more breaking changes that you need to evaluate before upgrading, not only `systemcrypto`.

> [!NOTE]
> The Microsoft build of Go does apply [other changes](#whats-different) to the official Go distribution, but `systemcrypto` is the most impactful, and the only one that adds additional dependencies.

## Additional Resources

The [project README](/README.md) provides more links to specialized documentation, context, and support resources for the Microsoft build of Go.
We recommend reading this migration guide for a broad overview of the process, then following applicable links in this document and the README for more specific details.

[msc10010]: https://liquid.microsoft.com/Web/Object/Read/MS.Security/Requirements/Microsoft.Security.Cryptography.10010
