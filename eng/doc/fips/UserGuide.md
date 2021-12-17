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
    - [crypto/ed25519](#cryptoed25519)
    - [crypto/elliptic](#cryptoelliptic)
    - [crypto/hmac](#cryptohmac)
    - [crypto/md5](#cryptomd5)
    - [crypto/rand](#cryptorand)
    - [crypto/rc4](#cryptorc4)
    - [crypto/sha1](#cryptosha1)
    - [crypto/sha256](#cryptosha256)
    - [crypto/sha512](#cryptosha512)
    - [crypto/subtle](#cryptosubtle)

## Using Go crypto APIs

This section describes how to use Go crypto APIs in a FIPS compliant manner. Packages and functions that do not appear here are not FIPS.

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

- If `len(key) == 16` then the cipher user is [EVP_aes_128_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ecb.html).
- If `len(key) == 24` then the cipher user is [EVP_aes_192_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ecb.html).
- If `len(key) == 32` then the cipher user is [EVP_aes_256_ecb](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ecb.html).

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
  - If `len(key) == 16` then the cipher user is [EVP_aes_128_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_gcm.html).
  - If `len(key) == 24` then the cipher user is [EVP_aes_192_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_gcm.html).
  - If `len(key) == 32` then the cipher user is [EVP_aes_256_gcm](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_gcm.html).
- `Seal(dst, nonce, plaintext, additionalData []byte) []byte` encrypts plaintext and uses additionalData to authenticate. It uses [EVP_EncryptUpdate](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html) for the encryption and [EVP_EncryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptFinal_ex.html) for authenticating.
- `Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` decrypts plaintext and uses additionalData to authenticate. It uses [EVP_DecryptUpdate](https://www.openssl.org/docs/man3.0/man3/EVP_DecryptUpdate.html) for the decryption and [EVP_DecryptFinal_ex](https://www.openssl.org/docs/man3.0/man3/EVP_DecryptFinal_ex.html) for authenticating.

If `cipher` is not FIPS compliant then `aead` is implemented by the standard Go library.

#### func [NewGCMWithNonceSize](https://pkg.go.dev/crypto/cipher#NewGCMWithNonceSize)

```go
func NewGCMWithNonceSize(cipher cipher.Block, size int) (aead cipher.AEAD, error)
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
func NewGCMWithTagSize(cipher cipher.Block, tagSize int) (aead cipher.AEAD, error)
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
func NewCBCDecrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining mode, using the given Block.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `cbc` implements the cipher.BlockMode using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher user is [EVP_aes_128_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html).
- If `len(key) == 24` then the cipher user is [EVP_aes_192_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html).
- If `len(key) == 32` then the cipher user is [EVP_aes_256_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html).

In all cases the cipher will have the padding disabled using [EVP_CIPHER_CTX_set_padding](https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_padding.html).

The cipher.BlockMode methods are implemented as follows:

- `BlockSize() int` always returns `16`.
- `CryptBlocks(dst, src []byte)` decrypts `src` into `dst` using [EVP_DecryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_DecryptUpdate.html).

If `block` is not FIPS compliant then `cbc` is implemented by the standard Go library.

#### func [NewCBCEncrypter](https://pkg.go.dev/crypto/cipher#NewCBCEncrypter)

```go
func NewCBCEncrypter(block Block, iv []byte) (cbc cipher.BlockMode)
```

NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode, using the given Block.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `cbc` implements the cipher.BlockMode using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher user is [EVP_aes_128_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html).
- If `len(key) == 24` then the cipher user is [EVP_aes_192_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html).
- If `len(key) == 32` then the cipher user is [EVP_aes_256_cbc](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html).


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
func NewCTR(block Block, iv []byte) (ctr cipher.BlockMode)
```

NewCTR returns a Stream which encrypts/decrypts using the given Block in counter mode.

**Parameters**

`block` must be an object created by [aes.NewCipher](https://pkg.go.dev/crypto/aes#NewCipher) in order to be FIPS compliant.

**Return values**

If `block` is FIPS compliant then `ctr` implements the cipher.Stream using an OpenSSL cipher that depends on the `block` key length:

- If `len(key) == 16` then the cipher user is [EVP_aes_128_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ctr.html).
- If `len(key) == 24` then the cipher user is [EVP_aes_192_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ctr.html).
- If `len(key) == 32` then the cipher user is [EVP_aes_256_ctr](https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ctr.html).


The cipher.Stream methods are implemented as follows:
- `XORKeyStream(dst, src []byte)` XORs each byte in the given slice using [EVP_EncryptUpdate](https://www.openssl.org/docs/manmaster/man3/EVP_EncryptUpdate.html).

If `block` is not FIPS compliant then `ctr` is implemented by the standard Go library.

#### func [NewOFB](https://pkg.go.dev/crypto/cipher#NewOFB)

NewOFB is not FIPS compliant.

#### func [StreamReader.Read](https://pkg.go.dev/crypto/cipher#StreamReader.Read)

```go
func (r StreamReader) Read(dst []byte) (n int, err error)
```

Can be used in a FIPS compliant manner if `r.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

#### func [StreamWriter.Write](https://pkg.go.dev/crypto/cipher#StreamWriter.Write)

```go
func (w StreamWriter) Write(src []byte) (n int, err error)
```

Can be used in a FIPS 140-2 compliant manner if `w.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

#### func [StreamWriter.Close](https://pkg.go.dev/crypto/cipher#StreamWriter.Close)

```go
func (w StreamWriter) Close() error
```

Can be used in a FIPS 140-2 compliant manner if `w.S` is an object created using cipher.NewCTR with FIPS compliant parameters.

### [crypto/des](https://pkg.go.dev/crypto/des)

Not FIPS compliant.

### [crypto/dsa](https://pkg.go.dev/crypto/dsa)

Not FIPS compliant.

### [crypto/dsa](https://pkg.go.dev/crypto/dsa)

Not FIPS compliant.

### [crypto/ecdsa](https://pkg.go.dev/crypto/ecdsa)

TODO

### [crypto/ed25519](https://pkg.go.dev/crypto/ed25519)

Not FIPS compliant.

### [crypto/elliptic](https://pkg.go.dev/crypto/elliptic)

TODO

### [crypto/hmac](https://pkg.go.dev/crypto/hmac)

TODO

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