# FIPS 140-2 User Guide

This document is a guide to the use of the Microsoft Go crypto package running on FIPS 140-2 compatibility mode -hereafter referred to as FIPS-, intended for use with the OpenSSL cryptographic library. It is intended as a technical reference for developers using, and system administrators installing, the Go tool set and the OpenSSL FIPS software, and for use in risk assessment reviews by security auditors. It is intended as a guide for annotation and more detailed explanation of the Go crypto documentation, and not as a replacement.

The Go crypto documentation is available online at https://pkg.go.dev/crypto.

- [FIPS 140-2 User Guide](#fips-140-2-user-guide)
  - [Using Go crypto APIs](#using-go-crypto-apis)
    - [crypto/aes](#cryptoaes)
      - [func NewCipher](#func-newcipher)
    - [crypto/cipher](#cryptocipher)
      - [func NewGCM](#func-newgcm)
      - [func NewGCMWithNonceSize](#func-newgcmwithnoncesize)
      - [func NewGCMWithTagSize](#func-newgcmwithtagsize)
      - [func NewCBCDecrypter](#func-newcbcdecrypter)
      - [func NewCBCEncrypter](#func-newcbcencrypter)
      - [func NewCFBDecrypter](#func-newcfbdecrypter)
      - [func NewCFBEncrypter](#func-newcfbencrypter)
      - [func NewCTR](#func-newctr)
      - [func NewOFB](#func-newofb)
      - [func StreamReader.Read](#func-streamreaderread)
      - [func StreamWriter.Write](#func-streamwriterwrite)
      - [func StreamWriter.Close](#func-streamwriterclose)
    - [crypto/des](#cryptodes)
    - [crypto/dsa](#cryptodsa)
    - [crypto/dsa](#cryptodsa-1)
    - [crypto/ecdsa](#cryptoecdsa)
      - [func Sign](#func-sign)
      - [func SignASN1](#func-signasn1)
      - [func Verify](#func-verify)
      - [func VerifyASN1](#func-verifyasn1)
      - [func SignASN1](#func-signasn1-1)
      - [func GenerateKey](#func-generatekey)
      - [func PrivateKey.Sign](#func-privatekeysign)
    - [crypto/ed25519](#cryptoed25519)
    - [crypto/elliptic](#cryptoelliptic)
    - [crypto/hmac](#cryptohmac)
      - [func Equal](#func-equal)
      - [func New](#func-new)
    - [crypto/md5](#cryptomd5)
    - [crypto/rand](#cryptorand)
    - [crypto/rc4](#cryptorc4)
    - [crypto/sha1](#cryptosha1)
    - [crypto/sha256](#cryptosha256)
    - [crypto/sha512](#cryptosha512)
    - [crypto/subtle](#cryptosubtle)

## Using Go crypto APIs

This section describes how to use Go crypto APIs in a FIPS compliant manner.

### [crypto/aes](https://pkg.go.dev/crypto/aes)

Package aes implements AES encryption (formerly Rijndael), as defined in U.S. Federal Information Processing Standards Publication 197.

#### func [NewCipher](https://pkg.go.dev/crypto/aes#NewCipher)

```go
func aes.NewCipher(key []byte) (cipher cipher.Block, err error)
```

NewCipher creates and returns a new [cipher.Block](https://pkg.go.dev/crypto/cipher#Block).

**Parameters**

`Key` is an AES key of length 16, 24, or 32.

**Return values**

`Cipher` implements the cipher.Block interface using an OpenSSL cipher function that depends on the `key` length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ecb.html).
- If `len(key) == 24` then the cipher used is [EVP_aes_192_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ecb.html).
- If `len(key) == 32` then the cipher used is [EVP_aes_256_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ecb.html).

The cipher.Block methods are implemented as follows:

- `BlockSize() int` always returns `16`.
- `Encrypt(dst, src []byte)` encrypts `src` into `dst` using [EVP_EncryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_EncryptUpdate.html).
- `Decrypt(dst, src []byte` decrypts `src` into `dst` using [EVP_DecryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_DecryptUpdate.html).

### [crypto/cipher](https://pkg.go.dev/crypto/cipher)

Package cipher implements standard block cipher modes that can be wrapped around low-level block cipher implementations.

#### func [NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM)

```go
func cipher.NewGCM(cipher cipher.Block) (aead cipher.AEAD, err error)
```

NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode with the standard nonce length.

**Parameters**

`Cipher` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `cipher` is FIPS compliant then `aead` implements the cipher.AEAD interface as follows:

- `NonceSize() int` always returns `12`.
- `Overhead() int` always returns `16`.
- The cipher used in `Seal` and `Open` depends on the key length used in `aes.NewCipher(key []byte)`:
  - If `len(key) == 16` then the cipher used is [EVP_aes_128_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_gcm.html).
  - If `len(key) == 24` then the cipher used is [EVP_aes_192_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_gcm.html).
  - If `len(key) == 32` then the cipher used is [EVP_aes_256_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_gcm.html).
- `Seal(dst, nonce, plaintext, additionalData []byte) []byte` encrypts plaintext and uses additionalData to authenticate. It uses [EVP_EncryptUpdate](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html) for the encryption and [EVP_EncryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptFinal_ex.html) for authenticating.
- `Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` decrypts plaintext and uses additionalData to authenticate. It uses [EVP_DecryptUpdate](https://www.openssl.org/docs/man3.0/man3/EVP_DecryptUpdate.html) for the decryption and [EVP_DecryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_DecryptFinal_ex.html) for authenticating.

If `cipher` is not FIPS compliant then `aead` is implemented by the standard Go library.

#### func [NewGCMWithNonceSize](https://pkg.go.dev/crypto/cipher#NewGCMWithNonceSize)

```go
func cipher.NewGCMWithNonceSize(cipher cipher.Block, size int) (aead cipher.AEAD, error)
```

NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which accepts nonces of the given length.

**Parameters**

`Cipher` must be an object created by aes.NewCipher and `size=12` in order to be FIPS compliant, else it will fall back to standard Go crypto.

**Return values**

`Aead` can have different implementations depending on the supplied parameters:

- If the parameters are FIPS compliant then `aead` behaves exactly as if it was created with cipher.NewGCM.
- If `cipher` is an object created by aes.NewCipher and `size != 12` then `aead` is implemented by the standard Go library using OpenSSL for encryption and decryption.
- Else `aead` is completely implemented by the standard Go library.

#### func [NewGCMWithTagSize](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize)

```go
func cipher.NewGCMWithTagSize(cipher cipher.Block, tagSize int) (aead cipher.AEAD, error)
```

NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which generates tags with the given length.

**Parameters**

`Cipher` must be an object created by aes.NewCipher and `tagSize=16` in order to be FIPS compliant, else it will fall back to standard Go crypto.

**Return values**

`Aead` can have different implementations depending on the supplied parameters:

- If the parameters are FIPS compliant then `aead` behaves exactly as if it was created with cipher.NewGCM.
- If `cipher` is an object created by aes.NewCipher and `tagSize != 16` then `aead` is implemented by the standard Go library using OpenSSL for encryption and decryption.
- Else `aead` is completely implemented by the standard Go library.

#### func [NewCBCDecrypter](https://pkg.go.dev/crypto/cipher#NewCBCDecrypter)

```go
func cipher.NewCBCDecrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining mode, using the given Block.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `cbc` implements the cipher.BlockMode using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html).
- If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html).
- If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html).

In all cases the cipher will have the padding disabled using [EVP_CIPHER_CTX_set_padding](https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_padding.html).

The cipher.BlockMode methods are implemented as follows:

- `BlockSize() int` always returns `16`.
- `CryptBlocks(dst, src []byte)` decrypts `src` into `dst` using [EVP_DecryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_DecryptUpdate.html).

If `block` is not FIPS compliant then `cbc` is implemented by the standard Go library.

#### func [NewCBCEncrypter](https://pkg.go.dev/crypto/cipher#NewCBCEncrypter)

```go
func cipher.NewCBCEncrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode, using the given Block.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `cbc` implements the cipher.BlockMode using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html).
- If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html).
- If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html).


The cipher.BlockMode methods are implemented as follows:

- `BlockSize() int` always returns `16`.
- `CryptBlocks(dst, src []byte)` encrypts `src` into `dst` using [EVP_EncryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_EncryptUpdate.html).

If `block` is not FIPS compliant then `cbc` is implemented by the standard Go library.

#### func [NewCFBDecrypter](https://pkg.go.dev/crypto/cipher#NewCFBDecrypter)

NewCFBDecrypter is not FIPS compliant.

#### func [NewCFBEncrypter](https://pkg.go.dev/crypto/cipher#NewCFBEncrypter)

NewCFBEncrypter is not FIPS compliant.

#### func [NewCTR](https://pkg.go.dev/crypto/cipher#NewCTR)

```go
func cipher.NewCTR(block Block, iv []byte) (ctr cipher.BlockMode)
```

NewCTR returns a Stream which encrypts/decrypts using the given Block in counter mode.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `ctr` implements the cipher.Stream using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ctr.html).
- If `len(key) == 24` then the cipher used is [EVP_aes_192_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ctr.html).
- If `len(key) == 32` then the cipher used is [EVP_aes_256_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ctr.html).


The cipher.Stream methods are implemented as follows:
- `XORKeyStream(dst, src []byte)` XORs each byte in the given slice using [EVP_EncryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_EncryptUpdate.html).

If `block` is not FIPS compliant then `ctr` is implemented by the standard Go library.

#### func [NewOFB](https://pkg.go.dev/crypto/cipher#NewOFB)

NewOFB is not FIPS compliant.

#### func [StreamReader.Read](https://pkg.go.dev/crypto/cipher#StreamReader.Read)

```go
func (r cipher.StreamReader) Read(dst []byte) (n int, err error)
```

Can be used in a FIPS compliant manner if `r.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

#### func [StreamWriter.Write](https://pkg.go.dev/crypto/cipher#StreamWriter.Write)

```go
func (w cipher.StreamWriter) Write(src []byte) (n int, err error)
```

Can be used in a FIPS 140-2 compliant manner if `w.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

#### func [StreamWriter.Close](https://pkg.go.dev/crypto/cipher#StreamWriter.Close)

```go
func (w cipher.StreamWriter) Close() error
```

Can be used in a FIPS 140-2 compliant manner if `w.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

### [crypto/des](https://pkg.go.dev/crypto/des)

Not FIPS compliant.

### [crypto/dsa](https://pkg.go.dev/crypto/dsa)

Not FIPS compliant.

### [crypto/dsa](https://pkg.go.dev/crypto/dsa)

Not FIPS compliant.

### [crypto/ecdsa](https://pkg.go.dev/crypto/ecdsa)

Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.

#### func [Sign](https://pkg.go.dev/crypto/ecdsa#Sign)

```go
func ecdsa.Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error)
```

Sign signs a hash using the private key.

**Parameters**

`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

`hash` must be the result of hashing a larger message using a FIPS compliant hashing algorithm. If this invariant is not met, Sign won't be FIPS compliant but still will sign the message.

**Return values**

`r` and `s` are generated using [ECDSA_sign](https://www.openssl.org/docs/man3.0/man3/ECDSA_sign.html).

#### func [SignASN1](https://pkg.go.dev/crypto/ecdsa#SignASN1)

```go
func ecdsa.SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (sig []byte, err error)
```

Sign signs a hash using the private key. It behaves as ecdsa.Sign but returns an ASN.1 encoded signature instead.

#### func [Verify](https://pkg.go.dev/crypto/ecdsa#Verify)

```go
func ecdsa.Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool
```

Verify verifies the signature in r, s of hash using the public key.

**Parameters**

There are no specific parameters requirements in order to be FIPS compliant.

**Return values**

Returns `true` if the signature is valid using [ECDSA_verify](https://www.openssl.org/docs/man3.0/man3/ECDSA_verify.html).

#### func [VerifyASN1](https://pkg.go.dev/crypto/ecdsa#VerifyASN1)

```go
func ecdsa.VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool
```

VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the public key. It behaves as ecdsa.VerifyASN1 but accepting an ASN.1 encoded signature instead.

#### func [SignASN1](https://pkg.go.dev/crypto/ecdsa#SignASN1)

```go
func ecdsa.SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (sig []byte, err error)
```

Sign signs a hash using the private key. It behaves as ecdsa.Sign but returns an ASN.1 encoded signature instead.

#### func [GenerateKey](https://pkg.go.dev/crypto/ecdsa#GenerateKey)

```go
func ecdsa.GenerateKey(c elliptic.Curve, rand io.Reader) (priv *ecdsa.PrivateKey, err error)
```

GenerateKey generates a public and private key pair.

**Parameters**

`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

**Return values**

The `priv` curve algorithm depends on the value of `c`:

- If `c.Params().Name == "P-224"` then curve is `NID_secp224r1`.
- If `c.Params().Name == "P-256"` then curve is `NID_X9_62_prime256v1`.
- If `c.Params().Name == "P-384"` then curve is `NID_secp384r1`.
- If `c.Params().Name == "P-521"` then curve is `NID_secp521r1`.

Other `c` values will result in an error.

#### func [PrivateKey.Sign](https://pkg.go.dev/crypto/ecdsa#PrivateKey.Sign)

```go
func (priv *ecdsa.PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
```

Sign signs digest with `priv`.

**Parameters**

`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

`digest` must be the result of hashing a larger message using a FIPS compliant hashing algorithm. If this invariant is not met, Sign won't be FIPS compliant but still will sign the message.

**Return values**

Signed messaged using [ECDSA_sign](https://www.openssl.org/docs/man3.0/man3/ECDSA_sign.html).

### [crypto/ed25519](https://pkg.go.dev/crypto/ed25519)

Not FIPS compliant.

### [crypto/elliptic](https://pkg.go.dev/crypto/elliptic)

Not FIPS compliant.

### [crypto/hmac](https://pkg.go.dev/crypto/hmac)

Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) as defined in U.S. Federal Information Processing Standards Publication 198.

#### func [Equal](https://pkg.go.dev/crypto/hmac#Equal)

```go
func hmac.Equal(mac1, mac2 []byte) bool
```

Equal compares two MACs for equality without leaking timing information.

This function does not implement any cryptographic algorithm, therefore out of FIPS scope.

#### func [New](https://pkg.go.dev/crypto/hmac#New)

```go
func hmac.New(h func() hash.Hash, key []byte) hash.Hash
```

New returns a new HMAC hash using the given hash.Hash type and key.

**Parameters**

`h` must be one of the following functions in order to be FIPS compliant: sha1.New, sha256.New, or sha512.New.

**Return values**

The hash.Hash methods are implemented as follows:
- `Write(p []byte) (int, error)` using [HMAC_Update](https://www.openssl.org/docs/manmaster/man3/HMAC_Update.html).
- `Sum(in []byte) []byte` using [HMAC_Final](https://www.openssl.org/docs/manmaster/man3/HMAC_Final.html).
- `Reset()` using [HMAC_Init_ex](https://www.openssl.org/docs/manmaster/man3/HMAC_Init_ex.html).

### [crypto/md5](https://pkg.go.dev/crypto/md5)

Not FIPS compliant.

### [crypto/rand](https://pkg.go.dev/crypto/rand)

TODO

### [crypto/rc4](https://pkg.go.dev/crypto/rc4)

Not FIPS compliant.

### [crypto/sha1](https://pkg.go.dev/crypto/sha1)

TODO

### [crypto/sha256](https://pkg.go.dev/crypto/sha256)

TODO

### [crypto/sha512](https://pkg.go.dev/crypto/sha512)

TODO

### [crypto/subtle](https://pkg.go.dev/crypto/subtle)

Does not contain crypto primitives, out of FIPS scope.