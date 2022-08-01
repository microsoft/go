# Microsoft Go 1.19 release notes

* [Upstream Go 1.19 release notes](https://tip.golang.org/doc/go1.19)

After the release of 1.19, 1.17 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

The 1.19 Microsoft build of Go includes some significant changes to FIPS support.

## Unified FIPS and non-FIPS Microsoft Go builds

As of 1.19, download the unified Microsoft Go toolset to build both standard Go crypto apps and FIPS apps. Use the `GOEXPERIMENT` environment variable[^1] to specify the crypto backend `go build` should include in the compiled app, or leave it alone to use Go standard crypto.

The unification improves Microsoft Go releases:

* No more delay between a standard servicing release and the corresponding FIPS servicing release.
* The VERSION file won't be missing from our FIPS branch builds/source because there's no longer a FIPS branch.

This was made possible by the upstream Go team merging the dev.boringcrypto branch into the main branch: [golang/go#51940 all: move dev.boringcrypto into main branch behind GOEXPERIMENT](https://github.com/golang/go/issues/51940). 

## Apps compiled with the OpenSSL backend now always use OpenSSL

Before 1.19, apps compiled with the OpenSSL backend only used OpenSSL if FIPS mode was enabled at runtime. If FIPS mode was not enabled, it would use Go standard crypto.

In 1.19, an app compiled with the OpenSSL backend using `GOEXPERIMENT=opensslcrypto`[^1] uses OpenSSL regardless of FIPS mode.

This makes our backend implementation more similar to the upstream implementation and improves performance when in FIPS mode.

In theory, this reduces portability of Go apps built with a crypto backend. Now, a Go app compiled with the OpenSSL backend requires OpenSSL to be present on the machine for the app to run, even if FIPS mode is not enabled. However, we think it's unlikely this will be an issue in practical Go usage.

More details: [microsoft/go#641 Always use OpenSSL backend when goexperiment=opensslcrypto](https://github.com/microsoft/go/issues/641).

## Added Windows FIPS support using CNG 

Microsoft Go 1.19 now includes a CNG ([Cryptography API: Next Generation](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal)) crypto backend for Windows, powered by the [microsoft/go-crypto-winnative](https://github.com/microsoft/go-crypto-winnative) module.

CNG can be used by setting the `GOEXPERIMENT` environment variable to `cngcrypto`[^1].

## OpenSSL backend fixes

We have also made a number of fixes and performance improvements in microsoft/go-crypto-openssl, the module we use to call OpenSSL APIs.

More details: [microsoft/go-crypto-openssl v0.2.0 Release Notes](https://github.com/microsoft/go-crypto-openssl/releases/tag/v0.2.0)

[^1]: See [the updated FIPS readme](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md) for more details on building and running apps with FIPS compatibility using Microsoft Go 1.19.
