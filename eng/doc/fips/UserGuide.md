# FIPS 140-2 User Guide

This document is a user guide for the Microsoft Go crypto package running on FIPS 140-2 compatibility mode (hereafter referred to as FIPS). It is intended as a technical reference for developers using, and system administrators installing, the Go toolset, and for use in risk assessment reviews by security auditors. This is not a replacement for the Go crypto documentation, rather it is a collection of notes and more detailed explanations in the context of FIPS compatibility.

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
    - [crypto/ecdh](#cryptoecdh)
      - [func P256](#func-p256)
      - [func P384](#func-p384)
      - [func P521](#func-p521)
      - [func X25519](#func-x25519)
      - [func PrivateKey.ECDH](#func-privatekeyecdh)
    - [crypto/ecdsa](#cryptoecdsa)
      - [func Sign](#func-sign)
      - [func SignASN1](#func-signasn1)
      - [func Verify](#func-verify)
      - [func VerifyASN1](#func-verifyasn1)
      - [func GenerateKey](#func-generatekey)
      - [func PrivateKey.Sign](#func-privatekeysign)
    - [crypto/ed25519](#cryptoed25519)
    - [crypto/elliptic](#cryptoelliptic)
    - [crypto/hmac](#cryptohmac)
      - [func Equal](#func-equal)
      - [func New](#func-new)
    - [crypto/md5](#cryptomd5)
    - [crypto/rand](#cryptorand)
      - [var Reader](#var-reader)
      - [func Int](#func-int)
      - [func Prime](#func-prime)
      - [func Read](#func-read)
    - [crypto/rc4](#cryptorc4)
      - [func NewCipher](#func-newcipher-1)
    - [crypto/sha1](#cryptosha1)
      - [func New](#func-new-1)
      - [func Sum](#func-sum)
    - [crypto/sha256](#cryptosha256)
      - [func New](#func-new-2)
      - [func New224](#func-new224)
      - [func Sum224](#func-sum224)
      - [func Sum256](#func-sum256)
    - [crypto/sha512](#cryptosha512)
      - [func New](#func-new-3)
      - [func New384](#func-new384)
      - [func New512\_224](#func-new512_224)
      - [func New512\_256](#func-new512_256)
      - [func Sum384](#func-sum384)
      - [func Sum512](#func-sum512)
      - [func Sum512\_224](#func-sum512_224)
      - [func Sum512\_256](#func-sum512_256)
    - [crypto/rsa](#cryptorsa)
      - [func DecryptOAEP](#func-decryptoaep)
      - [func DecryptPKCS1v15](#func-decryptpkcs1v15)
      - [func DecryptPKCS1v15SessionKey](#func-decryptpkcs1v15sessionkey)
      - [func EncryptPKCS1v15](#func-encryptpkcs1v15)
      - [func SignPKCS1v15](#func-signpkcs1v15)
      - [func SignPSS](#func-signpss)
      - [func VerifyPKCS1v15](#func-verifypkcs1v15)
      - [func VerifyPSS](#func-verifypss)
      - [func GenerateKey](#func-generatekey-1)
      - [func GenerateMultiPrimeKey](#func-generatemultiprimekey)
      - [func PrivateKey.Decrypt](#func-privatekeydecrypt)
      - [func PrivateKey.Sign](#func-privatekeysign-1)
    - [crypto/subtle](#cryptosubtle)
    - [crypto/tls](#cryptotls)

## Using Go crypto APIs

This section describes how to use Go crypto APIs in a FIPS compliant manner.

As a general rule, crypto APIs will delegate low-level operations to the crypto backend if these rules are met:

- The operation is supported by the crypto backend.
- The set of input parameters are supported by the crypto backend.

If any of the previous rules are not met, the operation will fall back to standard Go crypto unless otherwise specified. Standard Go crypto will behave as expected but is not FIPS compliant. There is not yet any way to configure the crypto APIs to panic instead of falling back to standard Go crypto. See [microsoft/go#428](https://github.com/microsoft/go/issues/428).

When reading the requirements section, the key word "must" is to be interpreted as a necessary condition to use the given API in a FIPS compliant manner.

### [crypto/aes](https://pkg.go.dev/crypto/aes)

Package aes implements AES encryption (formerly Rijndael), as defined in U.S. Federal Information Processing Standards Publication 197.

#### func [NewCipher](https://pkg.go.dev/crypto/aes#NewCipher)

```go
func aes.NewCipher(key []byte) (cipher cipher.Block, err error)
```

NewCipher creates and returns a new [cipher.Block](https://pkg.go.dev/crypto/cipher#Block).

**Requirements**

- `key` length must be 16, 24, or 32 bytes.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`cipher` implements the cipher.Block interface using a cipher function that depends on the `key` length:

- If `len(key) == 16` uses [EVP_aes_128_ecb].
- If `len(key) == 24` uses [EVP_aes_192_ecb].
- If `len(key) == 32` uses [EVP_aes_256_ecb].

The cipher.Block methods are implemented as follows:

- `BlockSize` always returns `16`.
- `Encrypt` uses [EVP_EncryptUpdate].
- `Decrypt` uses [EVP_DecryptUpdate].

</details>

<details><summary>CNG (click for details)</summary>

`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_ECB` mode, generated using [BCryptGenerateSymmetricKey].

The cipher.Block methods are implemented as follows:

- `BlockSize` always returns `16`.
- `Encrypt` uses [BCryptEncrypt].
- `Decrypt` uses [BCryptDecrypt].

</details>

### [crypto/cipher](https://pkg.go.dev/crypto/cipher)

Package cipher implements standard block cipher modes that can be wrapped around low-level block cipher implementations.

#### func [NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM)

```go
func cipher.NewGCM(cipher cipher.Block) (aead cipher.AEAD, err error)
```

NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode with the standard nonce length.

**Requirements**

- `cipher` must be an object created by [aes.NewCipher](#func-newcipher).

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`cipher` implements the cipher.AEAD interface using a cipher function that depends on the key length of cipher:

- `NonceSize` always returns `12`.
- `Overhead` always returns `16`.
- The cipher used in `Seal` and `Open` depends on the key length used in `aes.NewCipher(key []byte)`:
  - If `len(key) == 16` uses [EVP_aes_128_gcm].
  - If `len(key) == 24` uses [EVP_aes_192_gcm].
  - If `len(key) == 32` uses [EVP_aes_256_gcm].
- `Seal` uses [EVP_EncryptUpdate] for the encryption and [EVP_EncryptFinal_ex] for authenticating.
- `Open` uses [EVP_DecryptUpdate] for the decryption and [EVP_DecryptFinal_ex] for authenticating.

</details>

<details><summary>CNG (click for details)</summary>

`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_GCM` mode, generated using [BCryptGenerateSymmetricKey].

The cipher.Block methods are implemented as follows:
- `NonceSize` always returns `12`.
- `Overhead` always returns `16`.
- `Encrypt` uses [BCryptEncrypt].
- `Decrypt` uses [BCryptDecrypt].

</details>

#### func [NewGCMWithNonceSize](https://pkg.go.dev/crypto/cipher#NewGCMWithNonceSize)

```go
func cipher.NewGCMWithNonceSize(cipher cipher.Block, size int) (aead cipher.AEAD, error)
```

NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which accepts nonces of the given length.

**Requirements**

- `cipher` must be an object created by [aes.NewCipher](#func-newcipher).
- `size` must be 12.

**Implementation**

`aead` can have different implementations depending on the supplied parameters:

- If the parameters meet the requirements, then `aead` behaves exactly as if it was created with [aes.NewCipher](#func-newgcm).
- If `cipher` is an object created by [aes.NewCipher](#func-newcipher) and `size != 12`, then `aead` is implemented by the standard Go library and the crypto backend is only used for encryption and decryption.
- Else `aead` is completely implemented by the standard Go library.

#### func [NewGCMWithTagSize](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize)

```go
func cipher.NewGCMWithTagSize(cipher cipher.Block, tagSize int) (aead cipher.AEAD, error)
```

NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which generates tags with the given length.

**Requirements**

- `cipher` must be an object created by [aes.NewCipher](#func-newcipher).
- `tagSize` must be 16.

**Implementation**

`aead` can have different implementations depending on the supplied parameters:

- If the parameters meet the requirements, then `aead` behaves exactly as if it was created with [aes.NewCipher](#func-newgcm).
- If `cipher` is an object created by [aes.NewCipher](#func-newcipher) and `tagSize != 16` then `aead` is implemented by the standard Go library using the crypto backend for encryption and decryption.
- Else `aead` is completely implemented by the standard Go library.

#### func [NewCBCDecrypter](https://pkg.go.dev/crypto/cipher#NewCBCDecrypter)

```go
func cipher.NewCBCDecrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining mode, using the given Block.

**Requirements**

- `block` must be an object created by [aes.NewCipher](#func-newcipher). 

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`cbc` implements the cipher.BlockMode interface using a cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc].
- If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc].
- If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc].

In all cases the cipher will have the padding disabled using [EVP_CIPHER_CTX_set_padding].

The cipher.BlockMode methods are implemented as follows:

- `BlockSize` always returns `16`.
- `CryptBlocks` uses [EVP_DecryptUpdate].

</details>

<details><summary>CNG (click for details)</summary>

`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_CBC` mode, generated using [BCryptGenerateSymmetricKey].

The cipher.Block methods are implemented as follows:

- `BlockSize` always returns `16`.
- `CryptBlocks` uses [BCryptDecrypt].

</details>

#### func [NewCBCEncrypter](https://pkg.go.dev/crypto/cipher#NewCBCEncrypter)

```go
func cipher.NewCBCEncrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode, using the given Block.

**Requirements**

- `block` must be an object created by [aes.NewCipher](#func-newcipher). 

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`cbc` implements the cipher.BlockMode interface using a cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc].
- If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc].
- If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc].

The cipher.BlockMode methods are implemented as follows:

- `BlockSize` always returns `16`.
- `CryptBlocks` uses [EVP_EncryptUpdate].

</details>

<details><summary>CNG (click for details)</summary>

`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_CBC` mode, generated using [BCryptGenerateSymmetricKey].

The cipher.Block methods are implemented as follows:

- `BlockSize` always returns `16`.
- `CryptBlocks` uses [BCryptEncrypt].

</details>

#### func [NewCFBDecrypter](https://pkg.go.dev/crypto/cipher#NewCFBDecrypter)

cipher.NewCFBDecrypter is not implemented by any backend.

#### func [NewCFBEncrypter](https://pkg.go.dev/crypto/cipher#NewCFBEncrypter)

cipher.NewCFBEncrypter is not implemented by any backend.

#### func [NewCTR](https://pkg.go.dev/crypto/cipher#NewCTR)

```go
func cipher.NewCTR(block Block, iv []byte) (ctr cipher.Stream)
```

NewCTR returns a Stream which encrypts/decrypts using the given Block in counter mode.

**Requirements**

- The CNG backend does not implement this function.
- `block` must be an object created by [aes.NewCipher](#func-newcipher).

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`ctr` implements the cipher.Stream interface using a cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_ctr].
- If `len(key) == 24` then the cipher used is [EVP_aes_192_ctr].
- If `len(key) == 32` then the cipher used is [EVP_aes_256_ctr].

The cipher.Stream methods are implemented as follows:
- `XORKeyStream(dst, src []byte)` XORs each byte in the given slice using [EVP_EncryptUpdate].

</details>

#### func [NewOFB](https://pkg.go.dev/crypto/cipher#NewOFB)

cipher.NewOFB is not implemented by any backend.

#### func [StreamReader.Read](https://pkg.go.dev/crypto/cipher#StreamReader.Read)

```go
func (r cipher.StreamReader) Read(dst []byte) (n int, err error)
```

**Requirements**

- The CNG backend does not implement this function.
- `r.S` must be an object created by [cipher.NewCTR](#func-newctr).

#### func [StreamWriter.Write](https://pkg.go.dev/crypto/cipher#StreamWriter.Write)

```go
func (w cipher.StreamWriter) Write(src []byte) (n int, err error)
```

**Requirements**

- The CNG backend does not implement this function.
- `r.S` must be an object created by [cipher.NewCTR](#func-newctr).

#### func [StreamWriter.Close](https://pkg.go.dev/crypto/cipher#StreamWriter.Close)

```go
func (w cipher.StreamWriter) Close() error
```

Does not contain crypto algorithms, out of FIPS scope.

### [crypto/des](https://pkg.go.dev/crypto/des)

Not implemented by any backend.

### [crypto/dsa](https://pkg.go.dev/crypto/dsa)

Not implemented by any backend.

### [crypto/ecdh](https://pkg.go.dev/crypto/ecdh)

Package ecdh implements Elliptic Curve Diffie-Hellman over NIST curves and Curve25519.

**Implementation**

All supported curves implement the `ecdh.Curve` interface as follows:

<details><summary>OpenSSL (click for details)</summary>

 - `GenerateKey` uses [EVP_PKEY_keygen].
 - `NewPrivateKey` uses [EVP_PKEY_new].
 - `NewPublicKey` uses [EVP_PKEY_new].

</details>

<details><summary>CNG (click for details)</summary>

 - `GenerateKey` uses [BCryptGenerateKeyPair] and [BCryptExportKey].
 - `NewPrivateKey` uses [BCryptImportKeyPair].
 - `NewPublicKey` uses [BCryptImportKeyPair].

</details>

#### func [P256](https://pkg.go.dev/crypto/ecdh#P256)

```go
func ecdh.P256() ecdh.Curve
```

P256 returns a Curve which implements NIST P-256.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The curve uses `NID_X9_62_prime256v1`.

</details>

<details><summary>CNG (click for details)</summary>

The curve uses `BCRYPT_ECC_CURVE_NISTP256`.

</details>

#### func [P384](https://pkg.go.dev/crypto/ecdh#P384)

```go
func ecdh.P384() ecdh.Curve
```

P384 returns a Curve which implements NIST P-384.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The curve uses `NID_secp384r1`.

</details>

<details><summary>CNG (click for details)</summary>

The curve uses `BCRYPT_ECC_CURVE_NISTP384`.

</details>

#### func [P521](https://pkg.go.dev/crypto/ecdh#P521)

```go
func ecdh.P521() ecdh.Curve
```

P521 returns a Curve which implements NIST P-521.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The curve uses `NID_secp521r1`.

</details>

<details><summary>CNG (click for details)</summary>

The curve uses `BCRYPT_ECC_CURVE_NISTP521`.

</details>

#### func [X25519](https://pkg.go.dev/crypto/ecdh#X25519)

ecdh.X25519 is not implemented by any backend.

#### func [PrivateKey.ECDH](https://pkg.go.dev/crypto/ecdh#PrivateKey.ECDH)

```go
func (k *ecdh.PrivateKey) ECDH(remote *ecdh.PublicKey) ([]byte, error)
```

ECDH performs an ECDH exchange and returns the shared secret. The PrivateKey and PublicKey must use the same curve.

**Requirements**

- `remote` must be an object created from `ecdh.P256()`, `ecdh.P384()`, or `ecdh.P521()`.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The key is derived using [EVP_PKEY_derive].

</details>

<details><summary>CNG (click for details)</summary>

The key is derived using [BCryptDeriveKey].

</details>

### [crypto/ecdsa](https://pkg.go.dev/crypto/ecdsa)

Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.

#### func [Sign](https://pkg.go.dev/crypto/ecdsa#Sign)

```go
func ecdsa.Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error)
```

Sign signs a hash using the private key.

**Requirements**

- `rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.
- `hash` must be the result of hashing a message using a FIPS compliant hashing algorithm.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`r` and `s` are generated using [EVP_PKEY_sign].

</details>

<details><summary>CNG (click for details)</summary>

`r` and `s` are generated using [BCryptSignHash].

</details>

#### func [SignASN1](https://pkg.go.dev/crypto/ecdsa#SignASN1)

```go
func ecdsa.SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (sig []byte, err error)
```

SignASN1 signs a hash using the private key. It behaves as [ecdsa.Sign](#func-sign) but returns an ASN.1 encoded signature instead.

#### func [Verify](https://pkg.go.dev/crypto/ecdsa#Verify)

```go
func ecdsa.Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool
```

Verify verifies the signature in r, s of hash using the public key.

**Requirements**

There are no specific parameters requirements in order to be FIPS compliant.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The signature is verified using [EVP_PKEY_verify].

</details>

<details><summary>CNG (click for details)</summary>

The signature is verified using [BCryptVerifySignature].

</details>

#### func [VerifyASN1](https://pkg.go.dev/crypto/ecdsa#VerifyASN1)

```go
func ecdsa.VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool
```

VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the public key. It behaves as [ecdsa.Verify](#func-verify) but accepts an ASN.1 encoded signature instead.

#### func [GenerateKey](https://pkg.go.dev/crypto/ecdsa#GenerateKey)

```go
func ecdsa.GenerateKey(c elliptic.Curve, rand io.Reader) (priv *ecdsa.PrivateKey, err error)
```

GenerateKey generates a public and private key pair.

**Requirements**

- `c.Params().Name` must be one of the following values: P-224, P-256, P-384, or P-521.
- The CNG backend does not support P-224. 
- `rand` must be boring.RandReader, else GenerateKey will panic. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`priv` is a wrapper around an [EVP_PKEY] generated using [EVP_PKEY_keygen].

`priv` curve algorithm depends on the value of `c`:

- If `c.Params().Name == "P-224"` then curve is `NID_secp224r1`.
- If `c.Params().Name == "P-256"` then curve is `NID_X9_62_prime256v1`.
- If `c.Params().Name == "P-384"` then curve is `NID_secp384r1`.
- If `c.Params().Name == "P-521"` then curve is `NID_secp521r1`.

</details>

<details><summary>CNG (click for details)</summary>

`priv` is generated using [BCryptGenerateKeyPair].

`priv` [algorithm identifier] is `BCRYPT_ECDSA_ALGORITHM` and the [named elliptic curve] depends on the value of `c`:

- If `c.Params().Name == "P-224"` then curve is `BCRYPT_ECC_CURVE_NISTP224`.
- If `c.Params().Name == "P-256"` then curve is `BCRYPT_ECC_CURVE_NISTP256`.
- If `c.Params().Name == "P-384"` then curve is `BCRYPT_ECC_CURVE_NISTP384`.
- If `c.Params().Name == "P-521"` then curve is `BCRYPT_ECC_CURVE_NISTP521`.

</details>

#### func [PrivateKey.Sign](https://pkg.go.dev/crypto/ecdsa#PrivateKey.Sign)

```go
func (priv *ecdsa.PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
```

Sign signs `digest` with `priv`.

**Requirements**

- `rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.
- `digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The message is signed using [EVP_PKEY_sign].

</details>

<details><summary>CNG (click for details)</summary>

The message is signed using [BCryptSignHash].

</details>

### [crypto/ed25519](https://pkg.go.dev/crypto/ed25519)

Package ed25519 implements the Ed25519 signature algorithm. See https://ed25519.cr.yp.to/.

**Requirements**

The CNG backend and some old OpenSSL distributions don't support ED25519.
In those cases, the code will fall back to standard Go crypto.

#### func [GenerateKey](https://pkg.go.dev/crypto/ed25519#GenerateKey)

```go
func GenerateKey(rand io.Reader) (pub ed25519.PublicKey, priv ed25519.PrivateKey, error)
```

GenerateKey generates a public/private key pair using entropy from rand. If rand is nil, crypto/rand.Reader will be used.

**Requirements**

- `rand` must be boring.RandReader or nil, else GenerateKey will panic. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`pub` and `priv` are generated using [EVP_PKEY_keygen] with the `EVP_PKEY_ED25519` algorithm.

</details>

#### func [Sign](https://pkg.go.dev/crypto/ed25519#Sign)

```go
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte
```

Sign signs the message with privateKey and returns a signature. It will panic if len(privateKey) is not PrivateKeySize.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`message` is signed using [EVP_MD_CTX_new], [EVP_DigestSignInit] and [EVP_DigestSign].

</details>

#### func [Verify](https://pkg.go.dev/crypto/ed25519#Verify)

```go
func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool
```

Verify reports whether sig is a valid signature of message by publicKey. It will panic if len(publicKey) is not PublicKeySize.

**Requirements**

- OpenSSL version must be 1.1.1b or higher. Otherwise, falls back to standard Go crypto.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`message` is verified against `sig` using [EVP_MD_CTX_new], [EVP_DigestVerifyInit] and [EVP_DigestVerify].


</details>

#### func [VerifyWithOptions](https://pkg.go.dev/crypto/ed25519#VerifyWithOptions)

```go
func VerifyWithOptions(publicKey PublicKey, message, sig []byte, opts *Options) error
```

VerifyWithOptions reports whether sig is a valid signature of message by publicKey. A valid signature is indicated by returning a nil error. It will panic if len(publicKey) is not PublicKeySize.

**Requirements**

- Only `opts.Hash == nil && opts.Context == ""` is implemented using the OpenSSL backend. Other combinations fall back to standard Go code.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`message` is verified against `sig` using [EVP_MD_CTX_new], [EVP_DigestVerifyInit] and [EVP_DigestVerify].


</details>

#### func [NewKeyFromSeed](https://pkg.go.dev/crypto/ed25519#NewKeyFromSeed)

```go
func NewKeyFromSeed(seed []byte) (priv ed25519.PrivateKey)
```

NewKeyFromSeed calculates a private key from a seed. It will panic if len(seed) is not SeedSize.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`priv` is generated using [EVP_PKEY_new_raw_private_key] with the `EVP_PKEY_ED25519` algorithm.


</details>

#### func [PrivateKey.Sign](https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign)

```go
func (priv ed25519.PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)
```

Sign signs the given message with `priv`. `rand` is ignored and can be nil.

**Requirements**

- Only `opts.Hash == nil && opts.Context == ""` is implemented using the OpenSSL backend. Other combinations fall back to standard Go code.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`message` is signed using [EVP_MD_CTX_new], [EVP_DigestSignInit] and [EVP_DigestSign].

</details>

### [crypto/elliptic](https://pkg.go.dev/crypto/elliptic)

Not implemented by any backend, but to use `ecdsa.GenerateKey`, one of the following `elliptic.Curve` constructors must be used to specify the curve. See [`ecdsa.GenerateKey`](#func-generatekey) for additional requirements. As long as the requirements are met, only the name of the curve is used, not the curve parameters or methods implemented by standard Go crypto, allowing FIPS compliance.

```go
func elliptic.P224() elliptic.Curve
func elliptic.P256() elliptic.Curve
func elliptic.P384() elliptic.Curve
func elliptic.P521() elliptic.Curve
```

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

**Requirements**

- `h` must be one of the following functions: sha1.New, sha224.New, sha256.New, sha384.New, or sha512.New.
- The CNG backend does not support sha224.New. 

**Implementation**

<details><summary>OpenSSL 1.x (click for details)</summary>

The hmac is generated using [HMAC_CTX_new] and [HMAC_Init_ex].

The hash.Hash methods are implemented as follows:

- `Write` using [HMAC_Update].
- `Sum` using [HMAC_Final].
- `Reset` using [HMAC_Init_ex].

</details>

<details><summary>OpenSSL 3.x (click for details)</summary>

The hmac is generated using [EVP_MAC_CTX_new] and [EVP_MAC_init].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_MAC_update].
- `Sum` using [EVP_MAC_final].
- `Reset` using [EVP_MAC_init].

</details>

<details><summary>CNG (click for details)</summary>

The hmac is generated using [BCryptCreateHash] with the `BCRYPT_ALG_HANDLE_HMAC_FLAG` flag.

The [algorithm identifier] depends on the value of `h`:

- If `h == sha1.New` then algorithm is `BCRYPT_SHA1_ALGORITHM`.
- If `h == sha256.New` then algorithm is `BCRYPT_SHA256_ALGORITHM`.
- If `h == sha384.New` then algorithm is `BCRYPT_SHA384_ALGORITHM`.
- If `h == sha512.New` then algorithm is `BCRYPT_SHA512_ALGORITHM`.

The hash.Hash methods are implemented as follows:

- `Write` using [BCryptHashData].
- `Sum` using [BCryptFinishHash].
- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash].

</details>

### [crypto/md5](https://pkg.go.dev/crypto/md5)

Not implemented by any backend.

### [crypto/rand](https://pkg.go.dev/crypto/rand)

Package rand implements a cryptographically secure random number generator.

#### var [Reader](https://pkg.go.dev/crypto/rand#pkg-variables)

```go
var Reader io.Reader
```

Reader is a global, shared instance of a cryptographically secure random number generator.

It is assigned to boring.RandReader in the crypto/rand init function.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`rand.Reader` implements `io.Reader` using [RAND_bytes]

</details>

<details><summary>CNG (click for details)</summary>

`rand.Reader` implements `io.Reader` using [BCryptGenRandom]

</details>

#### func [Int](https://pkg.go.dev/crypto/rand#Int)

```go
func rand.Int(rand io.Reader, max *big.Int) (n *big.Int, err error)
```

Int returns a uniform random value in [0, max). It panics if max <= 0.

**Requirements**

- `rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

#### func [Prime](https://pkg.go.dev/crypto/rand#Prime)

```go
func Prime(rand io.Reader, bits int) (p *big.Int, err error)
```

Prime returns a number of the given bit length that is prime with high probability.

**Requirements**

- `rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

#### func [Read](https://pkg.go.dev/crypto/rand#Read)

```go
func Read(b []byte) (n int, err error)
```

Read is a helper function that calls rand.Reader.Read using io.ReadFull.

**Requirements**

- `rand.Reader` must be boring.RandReader. This invariant is normally met as `rand.Reader` is assigned to boring.RandReader in the crypto/rand init function.

### [crypto/rc4](https://pkg.go.dev/crypto/rc4)

Package rc4 implements RC4 encryption, as defined in Bruce Schneier's Applied Cryptography.

#### func [NewCipher](https://pkg.go.dev/crypto/rc4#NewCipher)

```go
func rc4.NewCipher() rc4.Cipher
```

NewCipher creates and returns a new Cipher. The key argument should be the RC4 key, at least 1 byte and at most 256 bytes.

**Requirements**

Some OpenSSL distributions don't implement RC4, e.g., OpenSSL 1.x compiled with `-DOPENSSL_NO_RC4` and OpenSSL 3.x that can't load the legacy provider.
In those cases, `rc4.NewCipher()` will fall back to standard Go crypto.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The cipher is generated using [EVP_CIPHER_CTX_new] and [EVP_CipherInit_ex] with the cipher type [EVP_rc4].

The rc4.Cipher methods are implemented as follows:

- `Reset` using [EVP_CIPHER_CTX_free].
- `XORKeyStream` using [EVP_EncryptUpdate].

</details>

<details><summary>CNG (click for details)</summary>

The cipher is generated using [BCryptGenerateSymmetricKey] using the `BCRYPT_RC4_ALGORITHM` mode.

The rc4.Cipher methods are implemented as follows:

- `Reset` using [BCryptDestroyKey].
- `XORKeyStream` using [BCryptEncrypt].

</details>

### [crypto/sha1](https://pkg.go.dev/crypto/sha1)

Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.

SHA-1 is an approved FIPS 140-2 hash algorithm although it is cryptographically broken and should not be used for secure applications.

#### func [New](https://pkg.go.dev/crypto/sha1#New)

```go
func sha1.New() hash.Hash
```

New returns a new hash.Hash computing the SHA1 checksum.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [EVP_sha1].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_DigestUpdate].
- `Sum` using [EVP_DigestFinal].
- `Reset` using [EVP_DigestInit].

</details>

<details><summary>CNG (click for details)</summary>

The hash is generated using [BCryptCreateHash] with the [algorithm identifier] `BCRYPT_SHA1_ALGORITHM`.

The hash.Hash methods are implemented as follows:

- `Write` using [BCryptHashData].
- `Sum` using [BCryptFinishHash].
- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash].

</details>

#### func [Sum](https://pkg.go.dev/crypto/sha1#Sum)

```go
func sha1.Sum(data []byte) [20]byte
```

Sum returns the SHA-1 checksum of the data.
It internally uses sha1.New() to compute the checksum.

### [crypto/sha256](https://pkg.go.dev/crypto/sha256)

Package sha256 implements the SHA224 and SHA256 hash algorithms as defined in FIPS 180-4.

#### func [New](https://pkg.go.dev/crypto/sha256#New)

```go
func sha256.New() hash.Hash
```

New returns a new hash.Hash computing the SHA256 checksum.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [EVP_sha256].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_DigestUpdate].
- `Sum` using [EVP_DigestFinal].
- `Reset` using [EVP_DigestInit].

</details>

<details><summary>CNG (click for details)</summary>

The hash is generated using [BCryptCreateHash] with the [algorithm identifier] `BCRYPT_SHA256_ALGORITHM`.

The hash.Hash methods are implemented as follows:

- `Write` using [BCryptHashData].
- `Sum` using [BCryptFinishHash].
- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash].

</details>

#### func [New224](https://pkg.go.dev/crypto/sha256#New224)

```go
func sha256.New224() hash.Hash
```

New224 returns a new hash.Hash computing the SHA224 checksum.

**Requirements**

- The CNG backend does not implement this function.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [EVP_sha24].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_DigestUpdate].
- `Sum` using [EVP_DigestFinal].
- `Reset` using [EVP_DigestInit].

</details>

#### func [Sum224](https://pkg.go.dev/crypto/sha256#Sum224)

```go
func sha256.Sum224(data []byte) [24]byte
```

Sum224 returns the SHA224 checksum of the data.
It internally uses sha224.New() to compute the checksum.

**Requirements**

- The CNG backend does not implement this function.

#### func [Sum256](https://pkg.go.dev/crypto/sha256#Sum256)

```go
func sha256.Sum256(data []byte) [32]byte
```

Sum256 returns the SHA256 checksum of the data.
It internally uses sha256.New() to compute the checksum.

### [crypto/sha512](https://pkg.go.dev/crypto/sha512)

Package sha512 implements the SHA-384, SHA-512, SHA-512/224, and SHA-512/256 hash algorithms as defined in FIPS 180-4.

#### func [New](https://pkg.go.dev/crypto/sha512#New)

```go
func sha512.New() hash.Hash
```

New returns a new hash.Hash computing the SHA-512 checksum.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [EVP_sha512].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_DigestUpdate].
- `Sum` using [EVP_DigestFinal].
- `Reset` using [EVP_DigestInit].

</details>

<details><summary>CNG (click for details)</summary>

The hash is generated using [BCryptCreateHash] with the [algorithm identifier] `BCRYPT_SHA512_ALGORITHM`.

The hash.Hash methods are implemented as follows:

- `Write` using [BCryptHashData].
- `Sum` using [BCryptFinishHash].
- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash].

</details>

#### func [New384](https://pkg.go.dev/crypto/sha512#New384)

```go
func sha512.New384() hash.Hash
```

New384 returns a new hash.Hash computing the SHA-384 checksum.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [EVP_sha384].

The hash.Hash methods are implemented as follows:

- `Write` using [EVP_DigestUpdate].
- `Sum` using [EVP_DigestFinal].
- `Reset` using [EVP_DigestInit].

</details>

<details><summary>CNG (click for details)</summary>

The hash is generated using [BCryptCreateHash] with the [algorithm identifier] `BCRYPT_SHA384_ALGORITHM`.

The hash.Hash methods are implemented as follows:

- `Write` using [BCryptHashData].
- `Sum` using [BCryptFinishHash].
- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash].

</details>

#### func [New512_224](https://pkg.go.dev/crypto/sha512#New512_224)

sha512.New512_224 is not implemented by any backend.

#### func [New512_256](https://pkg.go.dev/crypto/sha512#New512_256)

sha512.New512_256 is not implemented by any backend.

#### func [Sum384](https://pkg.go.dev/crypto/sha512#Sum384)

```go
func sha512.Sum384(data []byte) [48]byte
```

Sum384 returns the SHA384 checksum of the data.
It internally uses sha512.New384() to compute the checksum.

#### func [Sum512](https://pkg.go.dev/crypto/sha512#Sum512)

```go
func sha512.Sum512(data []byte) [64]byte
```

Sum512 returns the SHA512 checksum of the data.
It internally uses sha512.New() to compute the checksum.

#### func [Sum512_224](https://pkg.go.dev/crypto/sha512#Sum512_224)

sha512.Sum512_224 is not implemented by any backend.

#### func [Sum512_256](https://pkg.go.dev/crypto/sha512#Sum512_256)

sha512.Sum512_256 is not implemented by any backend.

### [crypto/rsa](https://pkg.go.dev/crypto/rsa)

Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.

#### func [DecryptOAEP](https://pkg.go.dev/crypto/rsa#DecryptOAEP)

```go
func rsa.DecryptOAEP(h hash.Hash, rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error)
```

DecryptOAEP decrypts ciphertext using RSA-OAEP.

**Requirements**

- `h` must be the result of one of the following functions: sha1.New(), sha224.New(), sha256.New(), sha384.New(), or sha512.New().
- The CNG backend does not support sha224.New().
- `rand` is not used. Blinding, if implemented, is delegated to crypto backend.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_OAEP_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`ciphertext` is decrypted using [BCryptDecrypt] with [BCRYPT_OAEP_PADDING_INFO] padding information and `BCRYPT_PAD_OAEP` pad mode.

</details>

#### func [DecryptPKCS1v15](https://pkg.go.dev/crypto/rsa#DecryptPKCS1v15)

```go
func rsa.DecryptPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error)
```

DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.

**Requirements**

- `rand` is not used. Blinding, if implemented, is delegated to crypto backend.
- `priv.Primes` length must be 2 when using the CNG backend.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`ciphertext` is decrypted using [BCryptDecrypt] with `BCRYPT_PAD_PKCS1` pad mode.

</details>

#### func [DecryptPKCS1v15SessionKey](https://pkg.go.dev/crypto/rsa#DecryptPKCS1v15SessionKey)

```go
func rsa.DecryptPKCS1v15SessionKey(rand io.Reader, priv *PrivateKey, ciphertext []byte, key []byte) error
```

DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding scheme from PKCS #1 v1.5.

**Requirements**

- `rand` is not used. Blinding, if implemented, is delegated to crypto backend.
- `priv.Primes` length must be 2 when using the CNG backend.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_PADDING` pad mode and copied into `key`.

</details>

<details><summary>CNG (click for details)</summary>

`ciphertext` is decrypted using [BCryptDecrypt] with `BCRYPT_PAD_PKCS1` pad mode and copied into `key`.

</details>

#### func [EncryptPKCS1v15](https://pkg.go.dev/crypto/rsa#EncryptPKCS1v15)

```go
func rsa.EncryptPKCS1v15(rand io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error)
```

**Requirements**

- `rand` must be boring.RandReader, else SignPSS will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`msg` is encrypted using [EVP_PKEY_encrypt] with `RSA_PKCS1_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`msg` is encrypted using [BCryptEncrypt] with `BCRYPT_PAD_PKCS1` pad mode.

</details>

#### func [SignPKCS1v15](https://pkg.go.dev/crypto/rsa#SignPKCS1v15)

```go
func rsa.SignPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error)
```

SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.

**Requirements**

- `rand` is not used. Blinding, if implemented, is delegated to crypto backend.
- `priv.Primes` length must be 2 when using the CNG backend.
- `hash` must be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, rypto.SHA384, or crypto.SHA512. Else SignPKCS1v15 will fail.
- The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.
- `hashed` must be the result of hashing a message using a FIPS compliant hashing algorithm.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`hashed` is signed using [EVP_PKEY_sign] with `RSA_PKCS1_PADDING`.

</details>

<details><summary>CNG (click for details)</summary>

`hashed` is signed using [BCryptSignHash] with [BCRYPT_PKCS1_PADDING_INFO] padding information and `BCRYPT_PAD_PKCS1` pad mode.

</details>

#### func [SignPSS](https://pkg.go.dev/crypto/rsa#SignPSS)

```go
func rsa.SignPSS(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error)
```

SignPSS calculates the signature of digest using PSS.

**Requirements**

- `rand` must be boring.RandReader, else SignPSS will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.
- `priv.Primes` length must be 2 when using the CNG backend.
- `hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, rypto.SHA384, or crypto.SHA512. Else SignPSS will fail.
- The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.
- `digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.
- `opts` can be nil.
- `opts.SaltLength` can either be a number of bytes, or one of the following constants: rsa.PSSSaltLengthAuto and rsa.PSSSaltLengthEqualsHash.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`digest` is signed using [EVP_PKEY_sign] with `RSA_PKCS1_PSS_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`digest` is signed using [BCryptSignHash] with [BCRYPT_PSS_PADDING_INFO] padding information and `BCRYPT_PAD_PSS` pad mode.

</details>

#### func [VerifyPKCS1v15](https://pkg.go.dev/crypto/rsa#VerifyPKCS1v15)

```go
func rsa.VerifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
```

VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.

**Requirements**

- `hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, rypto.SHA384, or crypto.SHA512. Else SignPSS will fail.
- The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.
- `hashed` must be the result of hashing a message using a FIPS compliant hashing algorithm.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`sig` is verified using [EVP_PKEY_verify] with `RSA_PKCS1_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`sig` is verified using [BCryptVerifySignature] with [BCRYPT_PKCS1_PADDING_INFO] padding information and `BCRYPT_PAD_PKCS1` pad mode.

</details>

#### func [VerifyPSS](https://pkg.go.dev/crypto/rsa#VerifyPSS)

```go
func rsa.VerifyPSS(pub *rsa.PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error
```

VerifyPSS verifies a PSS signature.

**Requirements**

- `hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, rypto.SHA384, or crypto.SHA512. Else VerifyPSS will fail.
- The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.
- `digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.
- `opts` can be nil.
- `opts.SaltLength` can either be a number of bytes, or one of the following constants: rsa.PSSSaltLengthAuto and rsa.PSSSaltLengthEqualsHash.
- The CNG backend does not support nil `opts` nor rsa.PSSSaltLengthAuto.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`sig` is verified using using [EVP_PKEY_verify] with `RSA_PKCS1_PSS_PADDING` pad mode.

</details>

<details><summary>CNG (click for details)</summary>

`sig` is verified using [BCryptVerifySignature] with [PSS_PADDING_INFO] padding information and `BCRYPT_PAD_PSS` pad mode.

</details>

#### func [GenerateKey](https://pkg.go.dev/crypto/rsa#GenerateKey)

```go
func rsa.GenerateKey(rand io.Reader, bits int) (priv *rsa.PrivateKey, err error)
```

GenerateKey generates a public and private key pair.

**Requirements**

- `rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.
- `bits` must be either 2048 or 3072.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`priv` is a wrapper around [EVP_PKEY] generated using [EVP_PKEY_keygen].

</details>

<details><summary>CNG (click for details)</summary>

`priv` is generated using [BCryptGenerateKeyPair] with the [algorithm identifier] `BCRYPT_RSA_ALGORITHM`.

</details>

#### func [GenerateMultiPrimeKey](https://pkg.go.dev/crypto/rsa#GenerateMultiPrimeKey)

```go
func rsa.GenerateMultiPrimeKey(rand io.Reader, nprimes int, bits int) (priv *rsa.PrivateKey, err error)
```

GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit size.

**Requirements**

- `rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.
- `nprimes` must be 2. 
- `bits` must be either 2048 or 3072.

**Implementation**

<details><summary>OpenSSL (click for details)</summary>

`priv` is a wrapper around [EVP_PKEY] generated using [EVP_PKEY_keygen].

</details>

<details><summary>CNG (click for details)</summary>

`priv` is generated using [BCryptGenerateKeyPair] with the [algorithm identifier] `BCRYPT_RSA_ALGORITHM`.

</details>

#### func [PrivateKey.Decrypt](https://pkg.go.dev/crypto/rsa#PrivateKey.Decrypt)

```go
func (priv *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
```

Decrypt decrypts `ciphertext` with `priv`.

The decrypt function depends on `opts`:

- If `opts` is nil, it calls [rsa.DecryptPKCS1v15](#func-decryptpkcs1v15)`(rand, priv, ciphertext)`.
- If `opts` type is `*rsa.OAEPOptions`, it calls [rsa.DecryptOAEP](#func-decryptoaep)`(opts.Hash.New(), rand, priv, ciphertext, opts.Label)`.
- If `opts` type is `*rsa.PKCS1v15DecryptOptions` and `opts.SessionKeyLen > 0`, it calls [rsa.DecryptPKCS1v15SessionKey](#func-decryptpkcs1v15sessionkey)`(rand, priv, ciphertext, plaintext)` with a random `plaintext`.
- If `opts` type is `*rsa.PKCS1v15DecryptOptions` and `opts.SessionKeyLen == 0`, it calls [rsa.DecryptPKCS1v15](#func-decryptpkcs1v15)`(rand, priv, ciphertext)`.
- Else it returns an error.

Each case may impose additional parameter requirements. After determining which case applies, check the linked function to find the additional restrictions.

#### func [PrivateKey.Sign](https://pkg.go.dev/crypto/rsa#PrivateKey.Sign)

```go
func (priv *rsa.PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
```

Sign signs `digest` with `priv`.

The sign function depends on `opts`:

- If `opts` type is `*rsa.PSSOptions`, it calls [rsa.SignPSS](#func-signpss)`(rand, priv, pssOpts.Hash, digest, opts)`
- Else it calls [rsa.SignPKCS1v15](#func-signpkcs1v15)`(rand, priv, opts.HashFunc(), digest)`.

Each case may impose additional parameter requirements. After determining which case applies, check the linked function to find the additional restrictions.

### [crypto/subtle](https://pkg.go.dev/crypto/subtle)

Does not contain crypto primitives, out of FIPS scope.

### [crypto/tls](https://pkg.go.dev/crypto/tls)

Package tls partially implements TLS 1.2, as specified in RFC 5246, and TLS 1.3, as specified in RFC 8446.

Package tls will automatically use FIPS compliant primitives implemented in other crypto packages, but it will accept non-FIPS ciphers and signature algorithms unless `crypto/tls/fipsonly` is imported.

When using TLS in FIPS-only mode the TLS handshake has the following restrictions:

- TLS versions:
  - `tls.VersionTLS12`
  - `tls.VersionTLS13`
- ECDSA elliptic curves:
  - `tls.CurveP256`
  - `tls.CurveP384`
  - `tls.CurveP521`
- Cipher suites for TLS 1.2:
  - `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - `tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- Cipher suites for TLS 1.3:
  - `tls.TLS_AES_128_GCM_SHA256`
  - `tls.TLS_AES_256_GCM_SHA384`
- x509 certificate public key:
  - `rsa.PublicKey` with a bit length of 2048 or 3072. Bit length of 4096 is still not supported, see [this issue](https://github.com/golang/go/issues/41147) for more info.
  - `ecdsa.PublicKey`  with a supported elliptic curve.
- Signature algorithms:
  - `tls.PSSWithSHA256`
  - `tls.PSSWithSHA384`
  - `tls.PSSWithSHA512`
  - `tls.PKCS1WithSHA256`
  - `tls.ECDSAWithP256AndSHA256`
  - `tls.PKCS1WithSHA384`
  - `tls.ECDSAWithP384AndSHA384`
  - `tls.PKCS1WithSHA512`
  - `tls.ECDSAWithP521AndSHA512`

[EVP_EncryptUpdate]: https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html
[EVP_DecryptUpdate]: https://www.openssl.org/docs/man3.0/man3/EVP_DecryptUpdate.html
[RAND_bytes]: https://www.openssl.org/docs/man3.0/man3/RAND_bytes.html
[EVP_PKEY]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY.html
[EVP_PKEY_new]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html
[EVP_PKEY_new_raw_private_key]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new_raw_private_key.html
[EVP_PKEY_keygen]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_keygen.html
[EVP_PKEY_sign]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_sign.html
[EVP_PKEY_verify]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_verify.html
[EVP_PKEY_encrypt]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
[EVP_PKEY_decrypt]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html
[EVP_PKEY_derive]: https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_derive.html
[EVP_MD_CTX_new]: https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_new.html
[EVP_DigestUpdate]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestUpdate.html
[EVP_DigestFinal]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestFinal.html
[EVP_DigestInit]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit.html
[EVP_DigestInit_ex]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit_ex.html
[EVP_DigestSign]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestSign.html
[EVP_DigestVerify]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerify.html
[EVP_DigestSign]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestSign.html
[EVP_DigestSignInit]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestSignInit.html
[EVP_DigestVerifyInit]: https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerifyInit.html
[EVP_EncryptFinal_ex]: https://www.openssl.org/docs/man3.0/man3/EVP_EncryptFinal_ex.html
[EVP_DecryptFinal_ex]: https://www.openssl.org/docs/man3.0/man3/EVP_DecryptFinal_ex.html
[EVP_CIPHER_CTX_set_padding]: https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_padding.html
[EVP_aes_128_ecb]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ecb.html
[EVP_aes_192_ecb]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ecb.html
[EVP_aes_256_ecb]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ecb.html
[EVP_aes_128_gcm]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_gcm.html
[EVP_aes_192_gcm]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_gcm.html
[EVP_aes_256_gcm]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_gcm.html
[EVP_aes_128_ctr]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ctr.html
[EVP_aes_192_ctr]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ctr.html
[EVP_aes_256_ctr]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ctr.html
[EVP_aes_128_cbc]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html
[EVP_aes_192_cbc]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html
[EVP_aes_256_cbc]: https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html
[EVP_rc4]: https://www.openssl.org/docs/man3.0/man3/EVP_rc4.html
[EVP_sha1]: https://www.openssl.org/docs/man3.0/man3/EVP_sha1.html
[EVP_sha224]: https://www.openssl.org/docs/man3.0/man3/EVP_sha224.html
[EVP_sha256]: https://www.openssl.org/docs/man3.0/man3/EVP_sha256.html
[EVP_sha384]: https://www.openssl.org/docs/man3.0/man3/EVP_sha384.html
[EVP_sha512]: https://www.openssl.org/docs/man3.0/man3/EVP_sha512.html
[HMAC_CTX_new]: https://www.openssl.org/docs/man3.0/man3/HMAC_CTX_new.html
[HMAC_Init_ex]: https://www.openssl.org/docs/man3.0/man3/HMAC_Init_ex.html
[HMAC_Update]: https://www.openssl.org/docs/man3.0/man3/HMAC_Update.html
[HMAC_Final]: https://www.openssl.org/docs/man3.0/man3/HMAC_Final.html
[EVP_MAC_CTX_new]: https://www.openssl.org/docs/man3.0/man3/EVP_MAC_CTX_new.html
[EVP_MAC_init]: https://www.openssl.org/docs/man3.0/man3/EVP_MAC_init.html
[EVP_MAC_update]: https://www.openssl.org/docs/man3.0/man3/EVP_MAC_update.html
[EVP_MAC_final]: https://www.openssl.org/docs/man3.0/man3/EVP_MAC_final.html
[EVP_CIPHER_CTX_new]: https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_new.html
[EVP_CipherInit_ex]: https://www.openssl.org/docs/man3.0/man3/EVP_CipherInit_ex.html
[EVP_CIPHER_CTX_free]: https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_free.html

[algorithm identifier]: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
[named elliptic curve]: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves
[BCryptGenRandom]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
[BCryptGenerateSymmetricKey]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
[BCryptGenerateKeyPair]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair
[BCryptImportKeyPair]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
[BCryptExportKey]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey
[BCryptEncrypt]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
[BCryptDecrypt]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
[BCryptSignHash]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash
[BCryptVerifySignature]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature
[BCryptCreateHash]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
[BCryptHashData]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
[BCryptFinishHash]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
[BCryptDestroyHash]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash
[BCRYPT_OAEP_PADDING_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_oaep_padding_info
[BCRYPT_PKCS1_PADDING_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_pkcs1_padding_info
[BCRYPT_PSS_PADDING_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_pss_padding_info
[BCryptDeriveKey]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey
[BCryptDestroyKey]: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey