# Crypto FIPS 140-2 support

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

### Go FIPS compliance

Go `crypto` package is not FIPS certified and the Go team has clearly stated that it is not going to happen, p.e. in [golang/go/issues/21734](https://github.com/golang/go/issues/21734#issuecomment-326980213) Adam Langley says: `The status of FIPS 140 for Go itself remains "no plans, basically zero chance"`.

On the other hand, Google maintains a branch that uses CGO and BoringSSL to implement various crypto primitives: https://github.com/golang/go/blob/dev.boringcrypto/README.boringcrypto.md. As BoringSSL is FIPS 140-2 certified, an application using that branch is more likely to be FIPS 140-2 compliant, yet Google does not provide any liability about the suitability of this code in relation to the FIPS 140-2 standard.

In addition to that, dev.boringcrypto branch also provides a mechanism to restricts all TLS configuration to FIPS-approved settings. The effect is triggered by importing the package anywhere in a program, as in:

```go
  import _ "crypto/tls/fipsonly"
```

## Microsoft Go fork FIPS compliance

Microsoft's Go runtime has been modified to implement some crypto primitives using CGO and OpenSSL, which is also FIPS 140-2 certified. To do so we have followed a similar approach as dev.boringcrypto branch, but using many learning, and even code, from the RedHat [go-toolset](https://developers.redhat.com/blog/2019/06/24/go-and-fips-140-2-on-red-hat-enterprise-linux) and also the .NET Runtime OpenSSL cryptography module.  

## Usage

FIPS mode, and therefore OPENSSL crypto backend, can be enabled using any of this options:

- Explicitly setting the environment variable`GOLANG_FIPS=1`.
- Implicitly enabling it by booting the Linux Kernel in FIPS mode, which sets the content of `/proc/sys/crypto/fips_enabled` to `1`. To opt-out from this approach, set `GOLANG_FIPS=0`.

Whichever is the approach used, the program initialization will panic if FIPS mode is requested but the Go runtime can't find a suitable OpenSSL shared library or OPENSSL FIPS mode can't be enabled.

The whole OpenSSL functionality can be disabled by building your program with `-tags no_openssl`.

## Features

### No code changes required

The Go crypto package implemented using OpenSSL does not require any code change to be used, just enable it as previously described and the runtime will automatically switch to using OpenSSL.

### Supported OpenSSL versions

We provide first-class support for OpenSSL v1.1.1, yet we will also run all tests against v1.0.2 and v1.1.1.

Support for OpenSSL v3.0.0 is in process.

### Dynamic OpenSSL linking

The OpenSSL API `libcrypto` is automatically loaded when initializing a FIPS-enabled program using [dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html), therefore its shared library search conventions also applies here.

The `libcrypto` shared library file name varies among different platforms, so a best-effort is done to find and load the right file:

- The base name is always `libcrypto.so.`
- Well-known version strings are appended to the base name, until the file is found, in the following order: `3` -> `1.1` -> `11` -> `111` -> `1.0.2` -> `1.0.0`.

This algorithm can be overwritten by setting the `GO_OPENSSL_VERSION_OVERRIDE` to the desired version string.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version used when building a program does not have to match with the OpenSSL version used when running it. It is even possible to build a program using plain Go crypto (i.e. setting `GOLANG_FIPS=0`) and then running that same program in FIPS mode.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain.

### TLS with FIPS-approved settings

The Go TLS stack will automatically use OpenSSL crypto primitives when running in FIPS mode. Yet, the FIPS 140-2 standard places additional restrictions on TLS communications, mainly on which cyphers and signers are allowed.

A program can import the `crypto/tls/fipsonly` to configure the Go TLS stack so it is compliant with these restrictions. Note that this can reduce the compatibility with old devices that do not support modern cryptography techniques such as TLS 1.2.

## Limitations

- FIPS mode is only supported in `linux_amd64`, but we plan to extend it to other platforms.
- Only the following crypto packages are backed by OpenSSL primitives: `crypto/aes`, `crypto/ecdsa`, `crypto/hmac`, `crypto/rand`, `crypto/rsa`, `crypto/sha1`, `crypto/sha256`, `crypto/sha512`.
- Hash primitives created by `sha512.New512_224` and `sha512.New512_256` are not backed by OpenSSL.

## Disclaimer

A program running in FIPS mode can claim it is using a FIPS-certified cryptographic module, but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.
