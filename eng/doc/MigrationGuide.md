# Migration Guide: Microsoft build of Go

This guide provides high-level guidance to help migrate from the [official Go distribution](https://go.dev/) to the [Microsoft build of Go](https://github.com/microsoft/go).
It's intended for developers who work on a Go project at Microsoft.

The Microsoft build of Go is designed to be a drop-in replacement for official Go.
It's a fork, and some runtime behavior slightly differs, but in most cases it has full compatibility with ordinary Go projects.
We expect that most projects don't require any Go code changes to work with the Microsoft build of Go.

Note that the Microsoft build of Go has [toolset telemetry enabled by default](https://devblogs.microsoft.com/go/microsoft-go-telemetry/) (opt-out telemetry).
See [the Data Collection policy for the Microsoft build of Go](/README.md#data-collection).

## Quick start

To comply with Microsoft internal policy for the use of Go, most projects need to:

1. Use the Microsoft build of Go **for CI (Continuous Integration) and build environments.**
    - If you use a version of Go prior to 1.25, you must enable `systemcrypto`. Starting with 1.25, `systemcrypto` is enabled by default.
    - If your build targets a preview platform (such as macOS), [additional configuration](fips/README.md#configuration-overview) may be required to enable `systemcrypto`.
1. **Test** your program.
    - It's important to test on all target platforms. The changes to runtime behavior are platform-specific.
1. Consider **whether your project must be FIPS compliant** and if so, review your project.
    - `systemcrypto` may be sufficient, however, you must review your project for compliant use of cryptography and a compliant environment.
    - For example, FedRAMP approval generally requires FIPS compliance.

For local development, it's not required to use the Microsoft build of Go.
Consider [installing the toolset](/README.md#download-and-install) on a developer machine if you need to use it to debug behavior that's specific to the Microsoft build.

Like the official Go distribution, the Microsoft build of Go has no Go runtime component that must be installed in the target environment.
Your Go application is still a single executable binary.
However, in some cases, it may now have additional dependencies.

## What's different?

The Microsoft build of Go includes [patches](/patches/) that:

- **Integrate `crypto` packages with system-provided cryptographic engines** on Linux and Windows. A macOS implementation is in preview.
- **Enable FIPS compliance** in a way compatible with Microsoft internal crypto policy: using system-provided engines.
- **Enhance FIPS mode runtime behavior** for scenarios we have encountered in Microsoft's and others' Go applications.
- **Add [toolset telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/)**, enabled by default.
- **Disable [GOTOOLCHAIN](https://go.dev/doc/toolchain) by default** to avoid mixups with the official Go distribution.
- **Remove use of undocumented Windows APIs** for compatibility, security, and compliance.

The patches directory at each Git tag specifies the exact code changes we have made to the official Go toolchain of that version.
If it's critical to you to understand the exact set of changes we've made, please review the patch files.

## Migration steps

This section describes some migration scenarios we know about and what path we recommend following for each one.

Note that any method of installing the Microsoft build of Go specified [in the project README file](/README.md#download-and-install) is valid.
If you see a good fit, go ahead and use it.
The scenarios in the following sections simply offer targeted guidance to help find the easiest approach.

### The `GoTool@0` Azure Pipelines step

The `GoTool@0` step doesn't currently support the Microsoft build of Go, and there is no equivalent step.
(See [microsoft/go#483](https://github.com/microsoft/go/issues/483).)

The most direct replacement is to use a `script` step to run [the cross-platform `go-install.ps1` script](/README.md#the-go-installps1-script).

### A `go` toolset that happens to be on my build agent

Some build agents (VMs, containers, etc.) have `go` conveniently pre-installed, but it's the official distribution of Go rather than the Microsoft build.
There is no universal migration. You may be able to:

* Request that your agent provider includes the Microsoft build of Go.
* Pick a different agent.
* Use a [Microsoft build of Go container image](https://github.com/microsoft/go-images/blob/microsoft/main/README.md) on the agent.

Otherwise, you need to find a suitable way to install it manually, such as [the cross-platform `go-install.ps1` script](/README.md#the-go-installps1-script).

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
See the above sections for [`GoTool@0`](#the-gotool0-azure-pipelines-step) and [container jobs](#azure-pipelines-container-jobs-using-the-official-golang-image) to find the best fit for your project.

### Direct download of the Go `tar.gz` or `zip` file

If you currently download an archived binary release of Go directly, you can switch to [Microsoft build of Go binary archives](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/Downloads.md).
That page provides both `aka.ms` links that redirect to the latest version and immutable links to specific releases.

## Testing

If it isn't clear that the correct build of Go was used to build your program, check which Go toolset built a specific Go binary by running:

`TODO`

To determine which Go distribution `go` is at any point in time, run:

`TODO`

### Common build issues

`TODO`

### Common test or runtime issues

### Missing OpenSSL and SymCrypt dependencies in Azure Linux 3

`TODO`: How does this appear to the user?
The solution is to add the required packages.
Required packages are:

- `openssl`
- `symcrypt` `>=` 103.6.0-1
- `symcrypt-openssl` (SCOSSL) `>=` 1.6.1-1

You may need to run `tdnf install -y openssl symcrypt symcrypt-openssl` or otherwise identify why these packages are not present.

### Panic: "crypto backend not available"
- **Cause:** Missing required crypto libraries or incompatible versions
- **Solution:** Install required crypto packages for your platform
- **Linux:** Install `openssl`, `symcrypt`, `symcrypt-openssl` packages
- **Azure Linux 3:** Ensure minimum versions SymCrypt-103.6.0-1, SymCrypt-OpenSSL-1.6.1-1

### Panic: "FIPS mode required but not enabled"
- **Cause:** Application built with `requirefips` tag but system not in FIPS mode
- **Solution:** Enable system FIPS mode or remove `requirefips` build constraint

### "No such file or directory" when loading libcrypto
- **Cause:** OpenSSL not installed or not in library search path
- **Solution:** Install OpenSSL package or set `LD_LIBRARY_PATH`
- **Override:** Use `GO_OPENSSL_VERSION_OVERRIDE` environment variable

`TODO`: take another pass at last three sections in general.

### Performance seems significantly worse

We expect performance to be comparable to standard Go.
Some patterns of using `crypto` may be more particularly impacted than others.

Please [contact us](/SUPPORT.md) for help with specific performance problems.

### Long path errors on Windows

Removing the use of undocumented Windows APIs unfortunately removed a feature that allows long paths to work by default for Go programs.

`TODO`: example
`TODO`: solution

### glibc resolution failure

**glibc version incompatibility**
- **Error:** "version 'GLIBC_X.XX' not found"
- **Cause:** Binary built on newer glibc trying to run on older system
- **Solution:** Rebuild on target system or older glibc version

The Microsoft build of Go uses cgo to integrate with system crypto libraries, which introduces dependencies on the build system's glibc version.
This creates important compatibility considerations:

**glibc Dependency:** Cgo introduces a dependency on the build system's version of glibc.
This may make the program incompatible with a different Linux distribution if it has a lower version of glibc.

**Deployment Strategies:**
- **Recommended:** Build and deploy using the same OS distribution and version
- **Cross-distribution:** Build on the oldest possible OS version for broader compatibility
- **Advanced:** Manually target an older version of glibc during compilation

**Container Considerations:**
- Programs built with system crypto cannot run in `scratch` containers
- Minimal containers need OpenSSL and SymCrypt packages installed
- Use Microsoft build of Go container images for pre-configured environments

`TODO`: examples of what failures look like to easily ctrl-f.
`TODO`: take another pass at section in general.

### Cryptography package failures while in FIPS mode

While in FIPS mode:

- Some crypto algorithms may be restricted
- TLS connections use FIPS-approved ciphers only
- Some legacy crypto operations may not be available

`TODO`: examples of what failures look like to easily ctrl-f. Link to FIPS doc with more description.

## Review project for FIPS compliance

If your project targets FIPS compliance, you need to do additional manual validation to ensure your project meets FIPS requirements.
These resources may help:

- Read the [FIPS Overview](fips/README.md) for background and additional build and runtime configuration
- See [CrossPlatformCryptography.md](CrossPlatformCryptography.md) for an overview of supported algorithms on various platforms.
- Review the [FIPS User Guide](fips/UserGuide.md) for deep API-specific guidance

For specific guidance within Microsoft:

- Read Microsoft.Security.Cryptography.10010 at https://liquid.microsoft.com/
- Contact the crypto board

## Additional Resources

The [project README](/README.md) provides more links to specialized documentation, context, and support resources for the Microsoft build of Go.
We recommend reading this migration guide for a broad overview of the process, then following applicable links in this document and the README for more specific details.
