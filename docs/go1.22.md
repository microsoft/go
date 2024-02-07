# Microsoft Go 1.22 release notes

After the release of 1.22, 1.20 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## Automatically configure TLS settings in FIPS mode

The crypto backends now automatically restrict the Go TLS stack's settings to allow only FIPS-compliant algorithms when running in FIPS mode.

In previous releases, adding `import _ "crypto/tls/fipsonly"` to a program's source code enables FIPS-compliant TLS, and this is no longer necessary. 

For more details, see the [FIPS readme](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md).

## New crypto algorithm backend support

Additional packages are now supported by the OpenSSL and CNG crypto backends:

* crypto/des
* crypto/ed25519
* crypto/md5
* crypto/rc4

The TLS PRF and HKDF algorithms are also now implemented by the crypto backends.

Not every algorithm implemented by a crypto backend is necessarily allowed in a FIPS-compliant program.
For more details about each algorithm, see the [FIPS User guide](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/UserGuide.md).
