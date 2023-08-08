# Microsoft Go 1.21 release notes

After the release of 1.21, 1.19 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## FIPS

The 1.21 release includes some changes to FIPS-related functionality. The following list is a summary of changes to the build functionality:

- Removes automatic Go standard library crypto fallback. If a crypto backend is selected but isn't supported, the build fails.
    - Before 1.21, the build automatically used the Go standard library crypto implementation. It wasn't immediately obvious that the fallback had occurred, so we've changed this to help prevent unexpected use of Go crypto.
    - This release adds the [`allowcryptofallback` experiment](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md#build-option-to-allow-go-standard-library-crypto-fallback) that reverts the effect of this change.
        - This *should not* be used: it adds risk of unintentionally using Go crypto. It exists for compatibility reasons internal to the Microsoft Go build itself and other extreme situations.
- Adds [`systemcrypto` experiment alias](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md#usage-build).
    - This `GOEXPERIMENT` selects a system-provided crypto backend based on the target platform. This shortcut is intended to help simplify build scripts and infrastructure.
    - `goexperiment.systemcrypto` can also be used as a build constraint (build tag) to only include a specific Go source file when a system-provided crypto backend is selected.
- Adds [`requirefips` build tag](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md#build-option-to-require-fips-mode).
    - This build tag makes the program fail if the crypto backend FIPS mode isn't enabled.
    - In most cases, this isn't necessary. We have added it to support cases where depending on the environment to set up FIPS mode correctly is insufficient.

For more details, see the [FIPS readme](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md) page, which has been updated significantly for this release.

## Feature that downloads newer versions of Go during the build introduced by upstream; disabled by default in Microsoft Go

Go 1.21 introduces [Go Toolchains](https://go.dev/doc/toolchain), which in some cases will download a new version of the Go toolset from upstream sources to perform the build. This feature could cause the Microsoft Go toolset to download an unpatched, upstream version of Go during `go build`, resulting in (among other issues) unintended use of Go crypto rather than OpenSSL/CNG.

To help avoid this problem, we have patched `$GOROOT/go.env` to contain `GOTOOLCHAIN=local` rather than `auto`. This disables the download feature by default. The need for this is acknowledged in the proposal thread:

> [zikaeroh commented](https://github.com/golang/go/issues/57001#issuecomment-1332650821):  
> Secondly, the automatic download/execution of binary releases of Go seems really surprising. I feel like it's going to be very awkward for Linux distributions to lose control of the toolchain in use without environment variables (especially if they patch Go). I do wonder how many distros might patch Go entirely to force `GOTOOLCHAIN=local` as the default. I believe there are also examples of corporate forks of Go (I've seen Microsoft's mentioned before), and those would also likely patch away this behavior becuase it'd be a bad thing for those to start bypassing the expected toolchain, especially without any sort of warning message that it's happening.

> [rsc commented](https://github.com/golang/go/issues/57001#issuecomment-1332657428):  
> I agree that some Linux distributions are likely to patch Go to default to `GOTOOLCHAIN=local`. That seems fine too, as long as users can still `go env -w GOTOOLCHAIN=auto`.

A build using Microsoft Go *should not* use `GOTOOLCHAIN=auto` as doing so would re-enable the undesired behavior.
