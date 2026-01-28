# Additional Features Provided by the Microsoft build of Go

This document provides a comprehensive overview of all features currently implemented in the Microsoft build of Go that are not part of the official Go distribution.

If you are trying to use the Microsoft build of Go but aren't looking for a precise guide to every feature, see [the Migration Guide](/eng/doc/MigrationGuide.md).

The `patches` directory at each Git tag specifies the exact code changes we have made to the official Go toolchain of that version.
If it's critical to you to understand the exact implementation details of all changes we've made, please review the patch files.

## Telemetry

The Microsoft build of Go collects [opt-out (enabled by default) toolset telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/).

See the [Data Collection policy for the Microsoft build of Go](/README.md#data-collection).

## System-provided cryptography backend

We have implemented changes to the Go standard library to call a platform-specific system-provided cryptography library rather than running the pure Go implementation.
Its main purposes are to comply with Microsoft's internal cryptography policies and implement FIPS 140 compliance.

As of Go 1.25, this feature is enabled by default.

Prior to Go 1.25, this feature can be enabled by setting the `GOEXPERIMENT` environment variable to `systemcrypto` before building a Go program.
Other methods of changing goexperiment settings also work.

See [the Migration Guide](/eng/doc/MigrationGuide.md) for more information about when, and how, to configure this feature.

More details are available in the [FIPS README](/eng/doc/fips/README.md).
These changes also include improvements to crypto library behavior to make it easier to comply with some FIPS requirements.

> [!NOTE]
> The purpose of this feature is to comply with the Microsoft internal cryptography policies, which mandate using system-provided cryptography modules.
> We encourage Go developers who aren't subject to those policies to continue using the official Go cryptography implementation.

## Version string changes to identify the Microsoft build of Go

### Embed Microsoft build of Go version information in binaries

This feature embeds Microsoft-specific version information into built Go binaries, making it easy to [identify the Microsoft build of Go toolset](/eng/doc/MicrosoftToolsetIdentification.md) and its specific version.

As of Go 1.26, this feature is enabled.

Every binary built by the Microsoft build of Go has a `microsoft_toolset_version` field in its list of buildinfo settings.
This string indicates the Microsoft build of Go version used to create the binary.
This information is accessible through `go version -m <program>` and the `debug/buildinfo` package's [BuildInfo](https://pkg.go.dev/runtime/debug#BuildInfo) struct `Settings` field.

For example, `go version -m <program>` produces output with a line like this, indicating that `program` was built by revision 1 of the Microsoft build of Go 1.26.0:

```
build   microsoft_toolset_version=go1.26.0-1-microsoft
```

The opt-in features described in the following sections can embed this string more deeply into built binaries, and change `runtime.Version()` to return the Microsoft version rather than the upstream version.

> [!NOTE]
> The Microsoft version string format is designed to be compatible with tools that rely on version parsing.
> It follows the expectations of the [go/version](https://pkg.go.dev/go/version) package.

### Runtime identification of Microsoft build

Microsoft build of Go 1.26 adds a new GODEBUG setting named `ms_version`.
It controls whether the Go runtime uses a Microsoft-specific version string in the output of `runtime.Version()`.

As of Go 1.26, this feature is available, but disabled by default.

In Go 1.27, we plan to change this feature to be enabled by default.

If you build a program that reports the Go version it uses, you may find this feature useful to provide more accurate data for diagnosis and status reporting.
This setting also affects the output of the `go version` command.

The possible values of `ms_version` are:

- `0`: `runtime.Version()` returns the upstream version string, for example: `go1.26.0`.
- `1`: `runtime.Version()` returns the Microsoft build of Go version string, for example: `go1.26.0-1-microsoft`.

> [!TIP]
> GODEBUG settings can be changed by setting the `GODEBUG` environment variable, but the default values of the settings can also be changed in several other ways, such as modifying the `go.mod` file.
> See [Go, Backwards Compatibility, and GODEBUG](https://go.dev/doc/godebug) for more information.

Using `ms_version` with the `go version` command allows you to easily determine if a given toolset is an up to date version of the Microsoft build of Go.
For example, in a Linux shell:

```
$ GODEBUG=ms_version=1 go version
go version go1.26.0-1-microsoft linux/amd64
```

> [!NOTE]
> To implement the `ms_version` feature, the Microsoft build of Go as of 1.26 always embeds *both* the upstream version string and the Microsoft version string into built binaries.
> This is independent from the `-ms_upstreamversion` linker flag described in the next section.

### Assign GoVersion to use Microsoft build identity

The Microsoft build of Go includes a feature to bake in the version string of the Microsoft build of Go instead of the upstream version.

As of Go 1.26, this feature is available, but disabled by default.

In Go 1.27, we plan to change this feature to be enabled by default.

> [!NOTE]
> Building `<program>` then running `go version <program>` shows a version baked into the program's binary, such as `go1.26.0`.
> This baked-in version is represented by `GoVersion` in [`debug/buildinfo.BuildInfo`](https://pkg.go.dev/runtime/debug#BuildInfo), so we call it the binary's `GoVersion`.
>
> The `GoVersion` is not necessarily the same version that `runtime.Version()` returns at runtime.
> These versions are controlled separately.

We added a linker flag `-ms_upstreamversion` that configures this behavior.
The possible values are:

- `0`: the `GoVersion` is assigned the Microsoft build of Go version string, for example: `go1.26.0-1-microsoft`.
- `1`: the `GoVersion` is assigned the upstream version string, for example: `go1.26.0`.

By default, as of Go 1.26, the `-ms_upstreamversion` flag is set to `1`.
Changing it from `1` to `0` to use this feature is done by passing the `-ms_upstreamversion=0` linker flag.
For example, use `-ldflags` with `go build`:

```
$ go build -ldflags="-ms_upstreamversion=0" program.go
$ go version program
program: go1.26.0-1-microsoft
```

> [!NOTE]
> The linker flag's value is inverted compared to the question "is this feature enabled".
> This is because our goal is to set it to `0` by default in Go 1.27 and beyond.
> `0` is a more ergonomic default for boolean Go flags than `1` is.

## Disable `GOTOOLCHAIN`

The Microsoft build of Go disables the `GOTOOLCHAIN` feature by default to ensure consistent builds and toolchain usage.
Specifically, the default `GOTOOLCHAIN` value is `local` rather than `auto`.

See <https://go.dev/doc/toolchain> for more information about `GOTOOLCHAIN`.

This change [is recommended by the Go team](https://github.com/golang/go/issues/57001#issuecomment-1332657428) for Linux distributions of Go, and the reasoning applies to the Microsoft build of Go as well.
We anticipate that otherwise, many who use the Microsoft build of Go would find themselves in a situation where their build switched to the official Go toolchain without their knowledge, and they would silently lose features they rely on for compliance.

For developers who are aware of this behavior and want it, it's possible to re-enable `GOTOOLCHAIN=auto`.

## Additional Windows support

### Use Windows Schannel settings for TLS

This Windows-only feature filters and orders cipher suites according to Windows Schannel settings.
It ensures TLS configuration matches the system's security policies at runtime.

> [!WARNING]
> This feature may reduce compatibility between TLS clients or servers and other implementations.
> Enable it only if your use case specifically requires alignment with Windows Schannel configuration settings.

As of Go 1.24.7, it can be enabled by setting the environment variable `GOEXPERIMENT` to `ms_tls_config_schannel` before building a Go program.
Other methods of changing goexperiment settings also work.

It is not supported and has no effect on Windows 8 and earlier and (the equivalent) Windows Server 2012 and earlier.

### Remove use of undocumented Windows APIs

For compatibility, security, and compliance reasons, we have removed the use of undocumented Windows APIs in the Microsoft build of Go.

Unfortunately, this may result in some loss of long-path functionality on some Windows systems.
See [the long-path troubleshooting section of the Migration Guide](/eng/doc/MigrationGuide.md#long-path-errors-on-windows) for an example.
