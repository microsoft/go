# Additional Features Provided by the Microsoft build of Go

This document provides a comprehensive overview of all features currently implemented in the Microsoft build of Go that are not part of the official Go distribution.

If you are trying to use the Microsoft build of Go but aren't looking for a precise guide to every feature, see [the Migration Guide](/eng/doc/MigrationGuide.md).

The `patches` directory at each Git tag specifies the exact code changes we have made to the official Go toolchain of that version.
If it's critical to you to understand the exact implementation details of all changes we've made, please review the patch files.

## Telemetry

The Microsoft build of Go collects [opt-out (enabled by default) toolset telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/).

See the [Telemetry documentation](/eng/doc/Telemetry.md) for details on what is collected and how to opt out.
See also the [Data Collection policy for the Microsoft build of Go](/README.md#data-collection).

## Position-independent executables on Linux

Starting with Go 1.28, the default build mode on Linux is `pie` on architectures that support internally linked position-independent executables: amd64, arm64, loong64, ppc64, ppc64le, and s390x.
Other architectures continue to use the upstream default `exe`.
The PIE default aligns with Microsoft's security policies and enables address space layout randomization (ASLR) for executables.

> [!NOTE]
> Windows and macOS (`darwin`) binaries already used PIE by default, prior to Go 1.28.

Builds on Linux using `-race` or `-asan` continue to use `exe` by default, not `pie`.
We do this because Go does not support PIE with the race detector on Linux, and using `pie` with `-asan` may break compatibility with system AddressSanitizer runtimes.

The default applies to `go build`, `go install`, `go run`, and `go test`, including cross-compilation.
It is independent of system crypto and does not require cgo or a C compiler.
Explicit build modes are unchanged; use `-buildmode=exe` to opt out.

On builds affected by the new PIE default, even pure-Go programs require a dynamic loader at runtime.
To produce a fully static executable instead, for example to run in a container without a dynamic loader, use:

```sh
CGO_ENABLED=0 go build -buildmode=exe
```

## Immediate binding for ELF binaries

Starting with Go 1.28, the linker enables immediate symbol binding (`BIND_NOW`) by default for dynamically linked ELF executables and shared libraries to align with Microsoft's security policies.
This applies to internal and external linking, with or without cgo or system crypto.

Go produces ELF binaries on Linux and several other Unix-like operating systems.
Windows and macOS use different executable formats and are unaffected.

Statically linked ELF binaries are unaffected by this change: they don't require dynamic symbol binding.

The dynamic linker resolves function symbols when a binary is loaded rather than when each function is first called.
Missing symbols are reported at load time rather than when the affected function is first called.

> [!NOTE]
> [RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) protects some relocation-related data from modification after loading.
> The linker marks a memory range for RELRO protection, and the dynamic linker makes that range read-only after applying relocations.
> Go enables RELRO for ELF PIE binaries and shared libraries, including executables built with the Microsoft build of Go [Linux PIE default](#position-independent-executables-on-linux).
>
> Immediate binding extends this protection to the global offset table entries used for function calls.
> Without immediate binding, these entries must remain writable so the dynamic linker can update them when each function is first called.

To restore the upstream linker default for ordinary executables, use:

```sh
go build -ldflags=-bindnow=false
```

For external linking, the C toolchain may still enable immediate binding by default.

## System-provided cryptography backend

We have implemented changes to the Go standard library to call a platform-specific system-provided cryptography library rather than running the pure Go implementation.
Its main purposes are to comply with Microsoft's internal cryptography policies and implement FIPS 140 compliance.

This feature is enabled by default on supported platforms.


See [the Migration Guide](/eng/doc/MigrationGuide.md) for more information about when, and how, to configure this feature.

More details are available in the [FIPS README](/eng/doc/fips/README.md).
These changes also include improvements to crypto library behavior to make it easier to comply with some FIPS requirements.

> [!NOTE]
> The purpose of this feature is to comply with the Microsoft internal cryptography policies, which mandate using system-provided cryptography modules.
> We encourage Go developers who aren't subject to those policies to continue using the official Go cryptography implementation.

## TLS setting alignment with Microsoft internal policies

The Microsoft build of Go can align the default TLS settings with Microsoft internal cryptography policies.
This allows developers to comply without changing application code that uses (or indirectly uses) the `crypto/tls` package.

Go 1.26 introduces `ms_tlsprofile`.
The possible values are:

- `default`: (default) use the recommended Microsoft TLS settings.
- `off`: use the upstream Go TLS settings.

Go 1.26 also introduces `ms_tlsx25519`.
The possible values of `ms_tlsx25519` are:

- `0` disables the X25519 and X25519MLKEM768 TLS groups.
- `1` (default) enables these groups.

Microsoft build of Go 1.28 introduces the `MS_GOTLSMLKEM` environment variable, which controls the default use of ML-KEM TLS key exchange in built programs.
The build-time values are:

- `0`: sets the program's `tlsmlkem` GODEBUG default to `0`.
- Unset or any other value: leaves the default unchanged.

With `tlsmlkem=0`, programs disable the X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 TLS groups by default.
The default use of classical groups, including X25519, is unchanged.
This setting applies independently of `ms_tlsprofile` and does not override explicit `tls.Config.CurvePreferences`.

`MS_GOTLSMLKEM` takes effect when the program is built, not when it runs.
The following command persists the setting for subsequent builds:

```sh
go env -w MS_GOTLSMLKEM=0
```

`go env -u MS_GOTLSMLKEM` removes the persisted setting.
Neither command changes programs that have already been built.

Explicit `godebug` directives in `go.mod` or `go.work` and `//go:debug` directives take precedence over this build-time default.
At runtime, `GODEBUG=tlsmlkem=1` overrides the built-in default and re-enables the ML-KEM groups, subject to the other TLS settings.

Microsoft build of Go `v1.27.2-2` introduces `ms_tlsmldsacert`, which controls ML-DSA advertisement in the `signature_algorithms_cert` extension.
The possible values are:

- `1` (default) advertises ML-DSA certificate signature algorithms, subject to the existing TLS version and FIPS restrictions.
- `0` omits ML-DSA-44, ML-DSA-65, and ML-DSA-87 from this extension in ClientHello and CertificateRequest messages to avoid a [known compatibility issue with TLS-inspecting middleboxes](https://github.com/golang/go/issues/81199).

The extension remains present, with its other algorithms and existing FIPS restrictions unchanged.
ML-DSA handshake signatures and ML-KEM key exchange remain available, subject to their existing restrictions.
This setting applies independently of `ms_tlsprofile`.
Certificate verification is unchanged, but disabling advertisement may cause peers to select a different certificate chain or fail if they require ML-DSA certificate signatures to be advertised.

These features operate independently from the system-provided cryptography backend feature.
They work the same way when the pure Go cryptography implementation is used.

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

As an additional safeguard against this risk, when the Microsoft build of Go detects that `GOTOOLCHAIN` has been manually changed to anything other than `local`, it prints a warning message to stderr and immediately exits with a non-zero status code.
This safeguard prevents forgotten or unintentional `GOTOOLCHAIN` settings from causing silent changes in toolchain behavior.
The printed message includes instructions to override the safeguard if necessary.

## Additional Windows support

### Use Windows Schannel settings for TLS

This Windows-only feature filters and orders cipher suites according to Windows Schannel settings.
It ensures TLS configuration matches the system's security policies at runtime.

> [!WARNING]
> This feature may reduce compatibility between TLS clients or servers and other implementations.
> Enable it only if your use case specifically requires alignment with Windows Schannel configuration settings.

It is not supported and has no effect on Windows 8 and earlier and (the equivalent) Windows Server 2012 and earlier.

### Remove use of undocumented Windows APIs

For compatibility, security, and compliance reasons, we have removed the use of undocumented Windows APIs in the Microsoft build of Go.

Unfortunately, this may result in some loss of long-path functionality on some Windows systems.
See [the long-path troubleshooting section of the Migration Guide](/eng/doc/MigrationGuide.md#long-path-errors-on-windows) for an example.
