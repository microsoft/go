# FIPS 140-2 User Guide

This document is a user guide for the Microsoft Go crypto package running on FIPS 140-2 compatibility mode (hereafter referred to as FIPS) when in use with the OpenSSL cryptographic library. It is intended as a technical reference for developers using, and system administrators installing, the Go toolset and the OpenSSL FIPS software, and for use in risk assessment reviews by security auditors. This is not a replacement for the Go crypto documentation, rather it is a collection of notes and more detailed explanations in the context of FIPS compatibility.

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
      - [func New512_224](#func-new512_224)
      - [func New512_256](#func-new512_256)
      - [func Sum384](#func-sum384)
      - [func Sum512](#func-sum512)
      - [func Sum512_224](#func-sum512_224)
      - [func Sum512_256](#func-sum512_256)
    - [crypto/subtle](#cryptosubtle)
    - [crypto/tls](#cryptotls)

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

`key` is an AES key of length 16, 24, or 32 bytes.

**Return values**

`cipher` implements the cipher.Block interface using an OpenSSL cipher function that depends on the `key` length:

- If `len(key) == 16` then the cipher used is [EVP_aes_128_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ecb.html).
- If `len(key) == 24` then the cipher used is [EVP_aes_192_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ecb.html).
- If `len(key) == 32` then the cipher used is [EVP_aes_256_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ecb.html).

The cipher.Block methods are implemented as follows:

- `BlockSize() int` always returns `16`.
- `Encrypt(dst, src []byte)` encrypts `src` into `dst` using [EVP_EncryptUpdate].
- `Decrypt(dst, src []byte` decrypts `src` into `dst` using [EVP_DecryptUpdate].

### [crypto/cipher](https://pkg.go.dev/crypto/cipher)

Package cipher implements standard block cipher modes that can be wrapped around low-level block cipher implementations.

#### func [NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM)

```go
func cipher.NewGCM(cipher cipher.Block) (aead cipher.AEAD, err error)
```

NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode with the standard nonce length.

**Parameters**

`cipher` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `cipher` is FIPS compliant then `aead` implements the cipher.AEAD interface as follows:

- `NonceSize() int` always returns `12`.
- `Overhead() int` always returns `16`.
- The cipher used in `Seal` and `Open` depends on the key length used in `aes.NewCipher(key []byte)`:
  - If `len(key) == 16` then the cipher used is [EVP_aes_128_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_gcm.html).
  - If `len(key) == 24` then the cipher used is [EVP_aes_192_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_gcm.html).
  - If `len(key) == 32` then the cipher used is [EVP_aes_256_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_gcm.html).
- `Seal(dst, nonce, plaintext, additionalData []byte) []byte` encrypts plaintext and uses additionalData to authenticate. It uses [EVP_EncryptUpdate] for the encryption and [EVP_EncryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptFinal_ex.html) for authenticating.
- `Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` decrypts plaintext and uses additionalData to authenticate. It uses [EVP_DecryptUpdate] for the decryption and [EVP_DecryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_DecryptFinal_ex.html) for authenticating.

If `cipher` is not FIPS compliant then `aead` is implemented by the standard Go library.

#### func [NewGCMWithNonceSize](https://pkg.go.dev/crypto/cipher#NewGCMWithNonceSize)

```go
func cipher.NewGCMWithNonceSize(cipher cipher.Block, size int) (aead cipher.AEAD, error)
```

NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which accepts nonces of the given length.

**Parameters**

`cipher` must be an object created by aes.NewCipher and `size = 12` in order to be FIPS compliant, else the function will fall back to standard Go crypto.

**Return values**

`aead` can have different implementations depending on the supplied parameters:

- If the parameters are FIPS compliant then `aead` behaves exactly as if it was created with cipher.NewGCM.
- If `cipher` is an object created by aes.NewCipher and `size != 12` then `aead` is implemented by the standard Go library and OpenSSL is only used for encryption and decryption.
- Else `aead` is completely implemented by the standard Go library.

#### func [NewGCMWithTagSize](https://pkg.go.dev/crypto/cipher#NewGCMWithTagSize)

```go
func cipher.NewGCMWithTagSize(cipher cipher.Block, tagSize int) (aead cipher.AEAD, error)
```

NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which generates tags with the given length.

**Parameters**

`cipher` must be an object created by aes.NewCipher and `tagSize = 16` in order to be FIPS compliant, else the function will fall back to standard Go crypto.

**Return values**

`aead` can have different implementations depending on the supplied parameters:

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
- `CryptBlocks(dst, src []byte)` decrypts `src` into `dst` using [EVP_DecryptUpdate].

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
- `CryptBlocks(dst, src []byte)` encrypts `src` into `dst` using [EVP_EncryptUpdate].

If `block` is not FIPS compliant then `cbc` is implemented by the standard Go library.

#### func [NewCFBDecrypter](https://pkg.go.dev/crypto/cipher#NewCFBDecrypter)

cipher.NewCFBDecrypter is not FIPS compliant.

#### func [NewCFBEncrypter](https://pkg.go.dev/crypto/cipher#NewCFBEncrypter)

cipher.NewCFBEncrypter is not FIPS compliant.

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
- `XORKeyStream(dst, src []byte)` XORs each byte in the given slice using [EVP_EncryptUpdate].

If `block` is not FIPS compliant then `ctr` is implemented by the standard Go library.

#### func [NewOFB](https://pkg.go.dev/crypto/cipher#NewOFB)

cipher.NewOFB is not FIPS compliant.

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

`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.

`hash` must be the result of hashing a message using a FIPS compliant hashing algorithm. If this invariant is not met, Sign won't be FIPS compliant but still will sign the message.

**Return values**

`r` and `s` are generated using [ECDSA_sign](https://www.openssl.org/docs/man3.0/man3/ECDSA_sign.html).

#### func [SignASN1](https://pkg.go.dev/crypto/ecdsa#SignASN1)

```go
func ecdsa.SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (sig []byte, err error)
```

SignASN1 signs a hash using the private key. It behaves as ecdsa.Sign but returns an ASN.1 encoded signature instead.

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

VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the public key. It behaves as ecdsa.Verify but accepts an ASN.1 encoded signature instead.

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

Sign signs `digest` with `priv`.

**Parameters**

`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

`digest` must be the result of hashing a message using a FIPS compliant hashing algorithm. If this invariant is not met, Sign won't be FIPS compliant but still will sign the message.

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

Package rand implements a cryptographically secure random number generator.

#### var [Reader](https://pkg.go.dev/crypto/rand#pkg-variables)

```go
var Reader io.Reader
```

Reader is a global, shared instance of a cryptographically secure random number generator.
It is assigned to boring.RandReader in the crypto/rand init function, which implements `io.Reader` by using the OpenSSL function [RAND_bytes](https://www.openssl.org/docs/man3.0/man3/RAND_bytes.html).


#### func [Int](https://pkg.go.dev/crypto/rand#Int)

```go
func rand.Int(rand io.Reader, max *big.Int) (n *big.Int, err error)
```

Int returns a uniform random value in [0, max). It panics if max <= 0.

**Parameters**

`rand` must be boring.RandReader in order to be FIPS compliant. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

#### func [Prime](https://pkg.go.dev/crypto/rand#Prime)

```go
func Prime(rand io.Reader, bits int) (p *big.Int, err error)
```

func Prime(rand io.Reader, bits int) (p *big.Int, err error)

**Parameters**

`rand` must be boring.RandReader in order to be FIPS compliant. `crypto/rand.Reader` normally meet this invariant as it is assigned to boring.RandReader in the crypto/rand init function.

#### func [Read](https://pkg.go.dev/crypto/rand#Read)

```go
func Read(b []byte) (n int, err error)
```

Read is a helper function that calls rand.Reader.Read using io.ReadFull. It is FIPS compliant as long as `rand.Reader == boring.RandReader`.

### [crypto/rc4](https://pkg.go.dev/crypto/rc4)

Not FIPS compliant.

### [crypto/sha1](https://pkg.go.dev/crypto/sha1)

Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.

SHA-1 is an approved FIPS 140-2 hash algorithm although it is cryptographically broken and should not be used for secure applications.

#### func [New](https://pkg.go.dev/crypto/sha1#New)

```go
func sha1.New() hash.Hash
```

New returns a new hash.Hash computing the SHA1 checksum.

**Return values**

The hash.Hash methods are implemented as follows:

- `Write(p []byte) (int, error)` using [SHA1_Update](https://www.openssl.org/docs/manmaster/man3/SHA1_Update.html).
- `Sum(in []byte) []byte` using [SHA1_Final](https://www.openssl.org/docs/manmaster/man3/SHA1_Final.html).
- `Reset()` using [SHA1_Init](https://www.openssl.org/docs/manmaster/man3/SHA1_Init.html).

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

**Return values**

The hash.Hash methods are implemented as follows:

- `Write(p []byte) (int, error)` using [SHA256_Update](https://www.openssl.org/docs/manmaster/man3/SHA256_Update.html).
- `Sum(in []byte) []byte` using [SHA256_Final](https://www.openssl.org/docs/manmaster/man3/SHA256_Final.html).
- `Reset()` using [SHA256_Init](https://www.openssl.org/docs/manmaster/man3/SHA256_Init.html).


#### func [New224](https://pkg.go.dev/crypto/sha256#New224)

```go
func sha256.New224() hash.Hash
```

New224 returns a new hash.Hash computing the SHA224 checksum.

**Return values**

The hash.Hash methods are implemented as follows:

- `Write(p []byte) (int, error)` using [SHA224_Update](https://www.openssl.org/docs/manmaster/man3/SHA224_Update.html).
- `Sum(in []byte) []byte` using [SHA224_Final](https://www.openssl.org/docs/manmaster/man3/SHA224_Final.html).
- `Reset()` using [SHA224_Init](https://www.openssl.org/docs/manmaster/man3/SHA224_Init.html).

#### func [Sum224](https://pkg.go.dev/crypto/sha256#Sum224)

```go
func sha256.Sum224(data []byte) [24]byte
```

Sum224 returns the SHA224 checksum of the data.
It internally uses sha224.New() to compute the checksum.

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

**Return values**

The hash.Hash methods are implemented as follows:

- `Write(p []byte) (int, error)` using [SHA512_Update](https://www.openssl.org/docs/manmaster/man3/SHA512_Update.html).
- `Sum(in []byte) []byte` using [SHA512_Final](https://www.openssl.org/docs/manmaster/man3/SHA512_Final.html).
- `Reset()` using [SHA512_Init](https://www.openssl.org/docs/manmaster/man3/SHA512_Init.html).

#### func [New384](https://pkg.go.dev/crypto/sha512#New384)

```go
func sha512.New384() hash.Hash
```

New384 returns a new hash.Hash computing the SHA-384 checksum.

**Return values**

The hash.Hash methods are implemented as follows:

- `Write(p []byte) (int, error)` using [SHA384_Update](https://www.openssl.org/docs/manmaster/man3/SHA384_Update.html).
- `Sum(in []byte) []byte` using [SHA384_Final](https://www.openssl.org/docs/manmaster/man3/SHA384_Final.html).
- `Reset()` using [SHA384_Init](https://www.openssl.org/docs/manmaster/man3/SHA384_Init.html).

#### func [New512_224](https://pkg.go.dev/crypto/sha512#New512_224)

sha512.New512_224 is not FIPS compliant.

#### func [New512_256](https://pkg.go.dev/crypto/sha512#New512_256)

sha512.New512_256 is not FIPS compliant.

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

sha512.Sum512_224 is not FIPS compliant.

#### func [Sum512_256](https://pkg.go.dev/crypto/sha512#Sum512_256)

sha512.Sum512_256 is not FIPS compliant.

### [crypto/subtle](https://pkg.go.dev/crypto/subtle)

Does not contain crypto primitives, out of FIPS scope.

### [crypto/tls](https://pkg.go.dev/crypto/tls)

Package tls partially implements TLS 1.2, as specified in RFC 5246, and TLS 1.3, as specified in RFC 8446.

Package tls will automatically use FIPS compliant primitives implemented in other crypto packages, but it will accept non-FIPS ciphers and signature algorithms unless `crypto/tls/fipsonly` is imported.

When using TLS in FIPS-only mode the TLS handshake has the following restrictions:

- TLS versions: `tls.VersionTLS12`
- ECDSA elliptic curves:
  - `tls.CurveP256`
  - `tls.CurveP384`
  - `tls.CurveP521`
- Cipher suites:
  - `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - `tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `tls.TLS_RSA_WITH_AES_128_GCM_SHA256`
  - `tls.TLS_RSA_WITH_AES_256_GCM_SHA384`
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

[EVP_EncryptUpdate]: https://www.openssl.org/docs/manmaster/man3/EVP_EncryptUpdate.html
[EVP_DecryptUpdate]: https://www.openssl.org/docs/manmaster/man3/EVP_DecryptUpdate.html