## The Microsoft build of Go crypto backends

The OpenSSL backend uses [go-crypto-openssl].
The CNG backend uses [go-crypto-winnative].
The CommonCrypto/CryptoKit backend uses [go-crypto-darwin].
For more general information about the backends, such as how to enable them, see the [Microsoft build of Go FIPS README](./README.md).

[go-crypto-openssl]: https://github.com/microsoft/go-crypto-openssl
[go-crypto-winnative]: https://github.com/microsoft/go-crypto-winnative
[go-crypto-darwin]: https://github.com/microsoft/go-crypto-darwin

> [!NOTE]
> The CNG backend uses a module called "bcrypt" to interact with CNG.
> Some identifiers and functions used by the CNG backend include a "bcrypt" prefix, referring to the "bcrypt" CNG module.
> For example, `BCryptGenRandom` is a function that generates random numbers using CNG.
>
> There is also a password hashing algorithm called "bcrypt".
> It is unrelated, and not in the scope of this document.

## Using Go crypto APIs

This section describes how to use Go crypto APIs in a FIPS compliant manner.

As a general rule, crypto APIs will delegate low-level operations to the crypto backend if these rules are met:

- The operation is supported by the crypto backend.
- The set of input parameters are supported by the crypto backend.

If any of the previous rules are not met, the operation will fall back to standard Go crypto unless otherwise specified. Standard Go crypto will behave as expected but is not FIPS compliant. There is not yet any way to configure the crypto APIs to panic instead of falling back to standard Go crypto. See [microsoft/go#428](https://github.com/microsoft/go/issues/428).

When reading the requirements section, the key word "must" is to be interpreted as a necessary condition to use the given API in a FIPS compliant manner.
