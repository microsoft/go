// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "strings"

// This file is the structured source of truth for the per-package, per-API
// content of the FIPS User Guide (eng/doc/fips/UserGuide.md). The generator in
// userguide.go renders all Markdown scaffolding (headings, anchors, code
// fences, requirement lists, and <details> implementation blocks) from these
// structures. Edit the data here rather than the generated Markdown.

// hashImpl builds the streaming-digest "Implementation" section shared by the
// md5, sha1, sha256, and sha512 constructors, which differ only by the
// underlying algorithm. evpMD is the OpenSSL message-digest link name (e.g.
// "EVP_sha256") and bcryptAlg is the CNG [algorithm identifier] (e.g.
// "BCRYPT_SHA256_ALGORITHM"). When bcryptAlg is empty the CNG backend is
// omitted, as CNG does not implement SHA-224.
func hashImpl(evpMD, bcryptAlg string) *ugImpl {
	backends := []ugBackend{
		openssl("The hash is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the algorithm [" + evpMD + "].\n" +
			"\n" +
			"The hash.Hash methods are implemented as follows:\n" +
			"\n" +
			"- `Write` using [EVP_DigestUpdate].\n" +
			"- `Sum` using [EVP_DigestFinal].\n" +
			"- `Reset` using [EVP_DigestInit]."),
	}
	if bcryptAlg != "" {
		backends = append(backends, cng("The hash is generated using [BCryptCreateHash] with the [algorithm identifier] `"+bcryptAlg+"`.\n"+
			"\n"+
			"The hash.Hash methods are implemented as follows:\n"+
			"\n"+
			"- `Write` using [BCryptHashData].\n"+
			"- `Sum` using [BCryptFinishHash].\n"+
			"- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash]."))
	}
	return &ugImpl{Backends: backends}
}

// sumDoc builds the documentation for the one-shot `Sum*` digest helpers, which
// all delegate to a streaming constructor. fn is the function name (e.g.
// "Sum256"), label is the checksum name shown in the prose (e.g. "SHA256"), and
// newFn is the constructor it delegates to (e.g. "sha256.New()").
func sumDoc(fn, label, newFn string) string {
	return fn + " returns the " + label + " checksum of the data.\n" +
		"It internally uses " + newFn + " to compute the checksum."
}

// notImplementedFunc builds a func entry for an API that no backend implements.
// qualified is the package-qualified name shown in the prose (e.g.
// "cipher.NewOFB"); the heading name is derived from the part after the dot.
func notImplementedFunc(qualified string) ugEntry {
	name := qualified
	if i := strings.LastIndex(qualified, "."); i >= 0 {
		name = qualified[i+1:]
	}
	return ugEntry{
		Kind: "func",
		Name: name,
		Doc:  qualified + " is not implemented by any backend.",
	}
}

// userGuideContent holds the User Guide package sections, in the order they are
// rendered. The set and ordering of packages is validated against the shared
// cryptoPackages registry so the User Guide stays in sync with
// CrossPlatformCryptography.md.
var userGuideContent = []ugPackage{
	{
		Import: "crypto/aes",
		Doc:    "Package aes implements AES encryption (formerly Rijndael), as defined in U.S. Federal Information Processing Standards Publication 197.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "NewCipher",
				Signature: "func aes.NewCipher(key []byte) (cipher cipher.Block, err error)",
				Doc:       "NewCipher creates and returns a new [cipher.Block](https://pkg.go.dev/crypto/cipher#Block).",
				Requirements: &ugRequirements{
					Items: []string{
						"`key` length must be 16, 24, or 32 bytes.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cipher` implements the cipher.Block interface using a cipher function that depends on the `key` length:\n" +
							"\n" +
							"- If `len(key) == 16` uses [EVP_aes_128_ecb].\n" +
							"- If `len(key) == 24` uses [EVP_aes_192_ecb].\n" +
							"- If `len(key) == 32` uses [EVP_aes_256_ecb].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `16`.\n" +
							"- `Encrypt` uses [EVP_EncryptUpdate].\n" +
							"- `Decrypt` uses [EVP_DecryptUpdate]."),
						cng("`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_ECB` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `16`.\n" +
							"- `Encrypt` uses [BCryptEncrypt].\n" +
							"- `Decrypt` uses [BCryptDecrypt]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/cipher",
		Doc:    "Package cipher implements standard block cipher modes that can be wrapped around low-level block cipher implementations.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "NewGCM",
				Signature: "func cipher.NewGCM(cipher cipher.Block) (aead cipher.AEAD, err error)",
				Doc:       "NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode with the standard nonce length.",
				Requirements: &ugRequirements{
					Items: []string{
						"`cipher` must be an object created by [aes.NewCipher](#func-newcipher).",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cipher` implements the cipher.AEAD interface using a cipher function that depends on the key length of cipher:\n" +
							"\n" +
							"- `NonceSize` always returns `12`.\n" +
							"- `Overhead` always returns `16`.\n" +
							"- The cipher used in `Seal` and `Open` depends on the key length used in `aes.NewCipher(key []byte)`:\n" +
							"  - If `len(key) == 16` uses [EVP_aes_128_gcm].\n" +
							"  - If `len(key) == 24` uses [EVP_aes_192_gcm].\n" +
							"  - If `len(key) == 32` uses [EVP_aes_256_gcm].\n" +
							"- `Seal` uses [EVP_EncryptUpdate] for the encryption and [EVP_EncryptFinal_ex] for authenticating.\n" +
							"- `Open` uses [EVP_DecryptUpdate] for the decryption and [EVP_DecryptFinal_ex] for authenticating."),
						cng("`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_GCM` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"- `NonceSize` always returns `12`.\n" +
							"- `Overhead` always returns `16`.\n" +
							"- `Encrypt` uses [BCryptEncrypt].\n" +
							"- `Decrypt` uses [BCryptDecrypt]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewGCMWithNonceSize",
				Signature: "func cipher.NewGCMWithNonceSize(cipher cipher.Block, size int) (aead cipher.AEAD, error)",
				Doc:       "NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which accepts nonces of the given length.",
				Requirements: &ugRequirements{
					Items: []string{
						"`cipher` must be an object created by [aes.NewCipher](#func-newcipher).",
						"`size` must be 12.",
					},
				},
				Impl: &ugImpl{
					Text: "`aead` can have different implementations depending on the supplied parameters:\n" +
						"\n" +
						"- If the parameters meet the requirements, then `aead` behaves exactly as if it was created with [aes.NewCipher](#func-newgcm).\n" +
						"- If `cipher` is an object created by [aes.NewCipher](#func-newcipher) and `size != 12`, then `aead` is implemented by the standard Go library and the crypto backend is only used for encryption and decryption.\n" +
						"- Else `aead` is completely implemented by the standard Go library.",
				},
			},
			{
				Kind:      "func",
				Name:      "NewGCMWithTagSize",
				Signature: "func cipher.NewGCMWithTagSize(cipher cipher.Block, tagSize int) (aead cipher.AEAD, error)",
				Doc:       "NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois Counter Mode, which generates tags with the given length.",
				Requirements: &ugRequirements{
					Items: []string{
						"`cipher` must be an object created by [aes.NewCipher](#func-newcipher).",
						"`tagSize` must be 16.",
					},
				},
				Impl: &ugImpl{
					Text: "`aead` can have different implementations depending on the supplied parameters:\n" +
						"\n" +
						"- If the parameters meet the requirements, then `aead` behaves exactly as if it was created with [aes.NewCipher](#func-newgcm).\n" +
						"- If `cipher` is an object created by [aes.NewCipher](#func-newcipher) and `tagSize != 16` then `aead` is implemented by the standard Go library using the crypto backend for encryption and decryption.\n" +
						"- Else `aead` is completely implemented by the standard Go library.",
				},
			},
			{
				Kind:      "func",
				Name:      "NewCBCDecrypter",
				Signature: "func cipher.NewCBCDecrypter(block Block, iv []byte) (cbc cipher.BlockMode)",
				Doc:       "NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining mode, using the given Block.",
				Requirements: &ugRequirements{
					Items: []string{
						"`block` must be an object created by [aes.NewCipher](#func-newcipher), [des.NewCipher](#func-newcipher-1), or [des.NewTripleDESCipher](#func-newtripledescipher).",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cbc` implements the cipher.BlockMode interface using a cipher that depends on the `block` key length:\n" +
							"\n" +
							"- For `aes.NewCipher`:\n" +
							"  - If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc].\n" +
							"  - If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc].\n" +
							"  - If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc].\n" +
							"- For `des.NewCipher`, the cipher used is [EVP_des_cbc].\n" +
							"- For `des.NewTripleDESCipher`, the cipher used is [EVP_des_ede3_cbc].\n" +
							"\n" +
							"In all cases the cipher will have the padding disabled using [EVP_CIPHER_CTX_set_padding].\n" +
							"\n" +
							"The cipher.BlockMode methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns the underlying cipher block size.\n" +
							"- `CryptBlocks` uses [EVP_DecryptUpdate]."),
						cng("`cipher` implements the cipher.Block interface using the underlying cipher [algorithm identifier]  with `BCRYPT_CHAIN_MODE_CBC` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns the underlying cipher block size.\n" +
							"- `CryptBlocks` uses [BCryptDecrypt]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewCBCEncrypter",
				Signature: "func cipher.NewCBCEncrypter(block Block, iv []byte) (cbc cipher.BlockMode)",
				Doc:       "NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode, using the given Block.",
				Requirements: &ugRequirements{
					Items: []string{
						"`block` must be an object created by [aes.NewCipher](#func-newcipher), [des.NewCipher](#func-newcipher-1), or [des.NewTripleDESCipher](#func-newtripledescipher).",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cbc` implements the cipher.BlockMode interface using a cipher that depends on the `block` key length:\n" +
							"\n" +
							"- For `aes.NewCipher`:\n" +
							"  - If `len(key) == 16` then the cipher used is [EVP_aes_128_cbc].\n" +
							"  - If `len(key) == 24` then the cipher used is [EVP_aes_192_cbc].\n" +
							"  - If `len(key) == 32` then the cipher used is [EVP_aes_256_cbc].\n" +
							"- For `des.NewCipher`, the cipher used is [EVP_des_cbc].\n" +
							"- For `des.NewTripleDESCipher`, the cipher used is [EVP_des_ede3_cbc].\n" +
							"\n" +
							"The cipher.BlockMode methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns the underlying cipher block size.\n" +
							"- `CryptBlocks` uses [EVP_EncryptUpdate]."),
						cng("`cipher` implements the cipher.Block interface using the underlying cipher [algorithm identifier]  with `BCRYPT_CHAIN_MODE_CBC` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns the underlying cipher block size.\n" +
							"- `CryptBlocks` uses [BCryptEncrypt]."),
					},
				},
			},
			notImplementedFunc("cipher.NewCFBDecrypter"),
			notImplementedFunc("cipher.NewCFBEncrypter"),
			{
				Kind:      "func",
				Name:      "NewCTR",
				Signature: "func cipher.NewCTR(block Block, iv []byte) (ctr cipher.Stream)",
				Doc:       "NewCTR returns a Stream which encrypts/decrypts using the given Block in counter mode.",
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
						"`block` must be an object created by [aes.NewCipher](#func-newcipher).",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`ctr` implements the cipher.Stream interface using a cipher that depends on the `block` key length:\n" +
							"\n" +
							"- If `len(key) == 16` then the cipher used is [EVP_aes_128_ctr].\n" +
							"- If `len(key) == 24` then the cipher used is [EVP_aes_192_ctr].\n" +
							"- If `len(key) == 32` then the cipher used is [EVP_aes_256_ctr].\n" +
							"\n" +
							"The cipher.Stream methods are implemented as follows:\n" +
							"- `XORKeyStream(dst, src []byte)` XORs each byte in the given slice using [EVP_EncryptUpdate]."),
					},
				},
			},
			notImplementedFunc("cipher.NewOFB"),
			{
				Kind:      "func",
				Name:      "StreamReader.Read",
				Signature: "func (r cipher.StreamReader) Read(dst []byte) (n int, err error)",
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
						"`r.S` must be an object created by [cipher.NewCTR](#func-newctr).",
					},
				},
			},
			{
				Kind:      "func",
				Name:      "StreamWriter.Write",
				Signature: "func (w cipher.StreamWriter) Write(src []byte) (n int, err error)",
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
						"`r.S` must be an object created by [cipher.NewCTR](#func-newctr).",
					},
				},
			},
			{
				Kind:      "func",
				Name:      "StreamWriter.Close",
				Signature: "func (w cipher.StreamWriter) Close() error",
				Doc:       "Does not contain crypto algorithms, out of FIPS scope.",
			},
		},
	},
	{
		Import: "crypto/des",
		Doc: "Package des implements the Data Encryption Standard (DES) and the Triple Data Encryption Algorithm (TDEA) as defined in U.S. Federal Information Processing Standards Publication 46-3.\n" +
			"\n" +
			"DES is cryptographically broken and should not be used for secure applications.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "NewCipher",
				Signature: "func des.NewCipher(key []byte) (cipher.Block, error)",
				Doc:       "NewCipher creates and returns a new cipher.Block.",
				Requirements: &ugRequirements{
					Items: []string{
						"`key` length must be 8 bytes.",
						"OpenSSL does not provide a DES implementation in FIPS mode. In that case, the code will fall back to standard Go crypto.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cipher` implements the cipher.Block interface using the [EVP_des_128_ecb] cipher function.\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `8`.\n" +
							"- `Encrypt` uses [EVP_EncryptUpdate].\n" +
							"- `Decrypt` uses [EVP_DecryptUpdate]."),
						cng("`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_DES_ALGORITHM` with `BCRYPT_CHAIN_MODE_ECB` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `8`.\n" +
							"- `Encrypt` uses [BCryptEncrypt].\n" +
							"- `Decrypt` uses [BCryptDecrypt]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewTripleDESCipher",
				Signature: "NewTripleDESCipher(key []byte) (cipher.Block, error)",
				Doc:       "NewTripleDESCipher creates and returns a new cipher.Block.",
				Requirements: &ugRequirements{
					Items: []string{
						"`key` length must be 24 bytes.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`cipher` implements the cipher.Block interface using the [EVP_des_ede3_ecb] cipher function.\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `8`.\n" +
							"- `Encrypt` uses [EVP_EncryptUpdate].\n" +
							"- `Decrypt` uses [EVP_DecryptUpdate]."),
						cng("`cipher` implements the cipher.Block interface using the [algorithm identifier] `BCRYPT_DES3_ALGORITHM` with `BCRYPT_CHAIN_MODE_ECB` mode, generated using [BCryptGenerateSymmetricKey].\n" +
							"\n" +
							"The cipher.Block methods are implemented as follows:\n" +
							"\n" +
							"- `BlockSize` always returns `8`.\n" +
							"- `Encrypt` uses [BCryptEncrypt].\n" +
							"- `Decrypt` uses [BCryptDecrypt]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/dsa",
		Doc:    "Not implemented by any backend.",
	},
	{
		Import: "crypto/ecdh",
		Doc:    "Package ecdh implements Elliptic Curve Diffie-Hellman over NIST curves and Curve25519.",
		Impl: &ugImpl{
			Text: "All supported curves implement the `ecdh.Curve` interface as follows:",
			Backends: []ugBackend{
				openssl(" - `GenerateKey` uses [EVP_PKEY_keygen].\n" +
					" - `NewPrivateKey` uses [EVP_PKEY_new].\n" +
					" - `NewPublicKey` uses [EVP_PKEY_new]."),
				cng(" - `GenerateKey` uses [BCryptGenerateKeyPair] and [BCryptExportKey].\n" +
					" - `NewPrivateKey` uses [BCryptImportKeyPair].\n" +
					" - `NewPublicKey` uses [BCryptImportKeyPair]."),
			},
		},
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "P256",
				Signature: "func ecdh.P256() ecdh.Curve",
				Doc:       "P256 returns a Curve which implements NIST P-256.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The curve uses `NID_X9_62_prime256v1`."),
						cng("The curve uses `BCRYPT_ECC_CURVE_NISTP256`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "P384",
				Signature: "func ecdh.P384() ecdh.Curve",
				Doc:       "P384 returns a Curve which implements NIST P-384.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The curve uses `NID_secp384r1`."),
						cng("The curve uses `BCRYPT_ECC_CURVE_NISTP384`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "P521",
				Signature: "func ecdh.P521() ecdh.Curve",
				Doc:       "P521 returns a Curve which implements NIST P-521.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The curve uses `NID_secp521r1`."),
						cng("The curve uses `BCRYPT_ECC_CURVE_NISTP521`."),
					},
				},
			},
			notImplementedFunc("ecdh.X25519"),
			{
				Kind:      "func",
				Name:      "PrivateKey.ECDH",
				Signature: "func (k *ecdh.PrivateKey) ECDH(remote *ecdh.PublicKey) ([]byte, error)",
				Doc:       "ECDH performs an ECDH exchange and returns the shared secret. The PrivateKey and PublicKey must use the same curve.",
				Requirements: &ugRequirements{
					Items: []string{
						"`remote` must be an object created from `ecdh.P256()`, `ecdh.P384()`, or `ecdh.P521()`.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The key is derived using [EVP_PKEY_derive]."),
						cng("The key is derived using [BCryptDeriveKey]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/ecdsa",
		Doc:    "Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "Sign",
				Signature: "func ecdsa.Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error)",
				Doc:       "Sign signs a hash using the private key.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.",
						"`hash` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`r` and `s` are generated using [EVP_PKEY_sign]."),
						cng("`r` and `s` are generated using [BCryptSignHash]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "SignASN1",
				Signature: "func ecdsa.SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (sig []byte, err error)",
				Doc:       "SignASN1 signs a hash using the private key. It behaves as [ecdsa.Sign](#func-sign) but returns an ASN.1 encoded signature instead.",
			},
			{
				Kind:      "func",
				Name:      "Verify",
				Signature: "func ecdsa.Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool",
				Doc:       "Verify verifies the signature in r, s of hash using the public key.",
				Requirements: &ugRequirements{
					Text: "There are no specific parameters requirements in order to be FIPS compliant.",
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The signature is verified using [EVP_PKEY_verify]."),
						cng("The signature is verified using [BCryptVerifySignature]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "VerifyASN1",
				Signature: "func ecdsa.VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool",
				Doc:       "VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the public key. It behaves as [ecdsa.Verify](#func-verify) but accepts an ASN.1 encoded signature instead.",
			},
			{
				Kind:      "func",
				Name:      "GenerateKey",
				Signature: "func ecdsa.GenerateKey(c elliptic.Curve, rand io.Reader) (priv *ecdsa.PrivateKey, err error)",
				Doc:       "GenerateKey generates a public and private key pair.",
				Requirements: &ugRequirements{
					Items: []string{
						"`c.Params().Name` must be one of the following values: P-224, P-256, P-384, or P-521.",
						"The CNG backend does not support P-224. ",
						"`rand` must be boring.RandReader, else GenerateKey will panic. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`priv` is a wrapper around an [EVP_PKEY] generated using [EVP_PKEY_keygen].\n" +
							"\n" +
							"`priv` curve algorithm depends on the value of `c`:\n" +
							"\n" +
							"- If `c.Params().Name == \"P-224\"` then curve is `NID_secp224r1`.\n" +
							"- If `c.Params().Name == \"P-256\"` then curve is `NID_X9_62_prime256v1`.\n" +
							"- If `c.Params().Name == \"P-384\"` then curve is `NID_secp384r1`.\n" +
							"- If `c.Params().Name == \"P-521\"` then curve is `NID_secp521r1`."),
						cng("`priv` is generated using [BCryptGenerateKeyPair].\n" +
							"\n" +
							"`priv` [algorithm identifier] is `BCRYPT_ECDSA_ALGORITHM` and the [named elliptic curve] depends on the value of `c`:\n" +
							"\n" +
							"- If `c.Params().Name == \"P-224\"` then curve is `BCRYPT_ECC_CURVE_NISTP224`.\n" +
							"- If `c.Params().Name == \"P-256\"` then curve is `BCRYPT_ECC_CURVE_NISTP256`.\n" +
							"- If `c.Params().Name == \"P-384\"` then curve is `BCRYPT_ECC_CURVE_NISTP384`.\n" +
							"- If `c.Params().Name == \"P-521\"` then curve is `BCRYPT_ECC_CURVE_NISTP521`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.Sign",
				Signature: "func (priv *ecdsa.PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)",
				Doc:       "Sign signs `digest` with `priv`.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader, else Sign will panic. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
						"`digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The message is signed using [EVP_PKEY_sign]."),
						cng("The message is signed using [BCryptSignHash]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/ed25519",
		Doc: "Package ed25519 implements the Ed25519 signature algorithm. See https://ed25519.cr.yp.to/.\n" +
			"\n" +
			"**Requirements**\n" +
			"\n" +
			"The CNG backend and some old OpenSSL distributions don't support ED25519.\n" +
			"In those cases, the code will fall back to standard Go crypto.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "GenerateKey",
				Signature: "func GenerateKey(rand io.Reader) (pub ed25519.PublicKey, priv ed25519.PrivateKey, error)",
				Doc:       "GenerateKey generates a public/private key pair using entropy from rand. If rand is nil, crypto/rand.Reader will be used.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader or nil. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`pub` and `priv` are generated using [EVP_PKEY_keygen] with the `EVP_PKEY_ED25519` algorithm."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Sign",
				Signature: "func Sign(privateKey ed25519.PrivateKey, message []byte) []byte",
				Doc:       "Sign signs the message with privateKey and returns a signature. It will panic if len(privateKey) is not PrivateKeySize.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`message` is signed using [EVP_MD_CTX_new], [EVP_DigestSignInit] and [EVP_DigestSign]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Verify",
				Signature: "func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool",
				Doc:       "Verify reports whether sig is a valid signature of message by publicKey. It will panic if len(publicKey) is not PublicKeySize.",
				Requirements: &ugRequirements{
					Items: []string{
						"OpenSSL version must be 1.1.1b or higher. Otherwise, falls back to standard Go crypto.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`message` is verified against `sig` using [EVP_MD_CTX_new], [EVP_DigestVerifyInit] and [EVP_DigestVerify].\n" +
							""),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "VerifyWithOptions",
				Signature: "func VerifyWithOptions(publicKey PublicKey, message, sig []byte, opts *Options) error",
				Doc:       "VerifyWithOptions reports whether sig is a valid signature of message by publicKey. A valid signature is indicated by returning a nil error. It will panic if len(publicKey) is not PublicKeySize.",
				Requirements: &ugRequirements{
					Items: []string{
						"Only `opts.Hash == nil && opts.Context == \"\"` is implemented using the OpenSSL backend. Other combinations fall back to standard Go code.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`message` is verified against `sig` using [EVP_MD_CTX_new], [EVP_DigestVerifyInit] and [EVP_DigestVerify].\n" +
							""),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewKeyFromSeed",
				Signature: "func NewKeyFromSeed(seed []byte) (priv ed25519.PrivateKey)",
				Doc:       "NewKeyFromSeed calculates a private key from a seed. It will panic if len(seed) is not SeedSize.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`priv` is generated using [EVP_PKEY_new_raw_private_key] with the `EVP_PKEY_ED25519` algorithm.\n" +
							""),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.Sign",
				Signature: "func (priv ed25519.PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)",
				Doc:       "Sign signs the given message with `priv`. `rand` is ignored and can be nil.",
				Requirements: &ugRequirements{
					Items: []string{
						"Only `opts.Hash == nil && opts.Context == \"\"` is implemented using the OpenSSL backend. Other combinations fall back to standard Go code.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`message` is signed using [EVP_MD_CTX_new], [EVP_DigestSignInit] and [EVP_DigestSign]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/elliptic",
		Doc: "Not implemented by any backend, but to use `ecdsa.GenerateKey`, one of the following `elliptic.Curve` constructors must be used to specify the curve. See [`ecdsa.GenerateKey`](#func-generatekey) for additional requirements. As long as the requirements are met, only the name of the curve is used, not the curve parameters or methods implemented by standard Go crypto, allowing FIPS compliance.\n" +
			"\n" +
			"```go\n" +
			"func elliptic.P224() elliptic.Curve\n" +
			"func elliptic.P256() elliptic.Curve\n" +
			"func elliptic.P384() elliptic.Curve\n" +
			"func elliptic.P521() elliptic.Curve\n" +
			"```",
	},
	{
		Import: "crypto/hkdf",
		Doc: "Package hkdf implements the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in RFC 5869.\n" +
			"\n" +
			"The hash function passed to the HKDF APIs must be one supported by the crypto backend (see [crypto/sha1](#cryptosha1), [crypto/sha256](#cryptosha256), [crypto/sha512](#cryptosha512), and [crypto/sha3](#cryptosha3)). If the hash is not supported by the backend, the operation falls back to standard Go crypto.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "Extract",
				Signature: "func hkdf.Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error)",
				Doc:       "Extract generates a pseudorandom key for use with [hkdf.Expand](#func-expand) from the input `secret` and an optional `salt`.",
				Requirements: &ugRequirements{
					Items: []string{
						"`h` must return a hash supported by the crypto backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The pseudorandom key is derived using the HKDF KDF in extract-only mode.\n" +
							"On OpenSSL 1.x this uses [EVP_PKEY_derive] with an `EVP_PKEY_HKDF` context configured with `EVP_PKEY_HKDF_MODE_EXTRACT_ONLY`.\n" +
							"On OpenSSL 3.x this uses [EVP_KDF_derive] with the `HKDF` KDF set to extract-only mode."),
						cng("The pseudorandom key is derived using [BCryptKeyDerivation] with the `BCRYPT_HKDF_ALGORITHM` [algorithm identifier], setting the hash with the `BCRYPT_HKDF_HASH_ALGORITHM` property and finalizing with the `BCRYPT_HKDF_SALT_AND_FINALIZE` property."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Expand",
				Signature: "func hkdf.Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) ([]byte, error)",
				Doc:       "Expand derives a key of `keyLength` bytes from the given `pseudorandomKey` and optional `info`, returned by [hkdf.Extract](#func-extract).",
				Requirements: &ugRequirements{
					Items: []string{
						"`h` must return a hash supported by the crypto backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The key is derived using the HKDF KDF in expand-only mode.\n" +
							"On OpenSSL 1.x this uses [EVP_PKEY_derive] with an `EVP_PKEY_HKDF` context configured with `EVP_PKEY_HKDF_MODE_EXPAND_ONLY`.\n" +
							"On OpenSSL 3.x this uses [EVP_KDF_derive] with the `HKDF` KDF set to expand-only mode."),
						cng("The key is derived using [BCryptKeyDerivation] with the `BCRYPT_HKDF_ALGORITHM` [algorithm identifier], setting the pseudorandom key with the `BCRYPT_HKDF_PRK_AND_FINALIZE` property and the info with the `BCRYPT_HKDF_INFO` parameter."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Key",
				Signature: "func hkdf.Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLength int) ([]byte, error)",
				Doc: "Key derives a key of `keyLength` bytes from the given `secret`, `salt`, and `info`.\n" +
					"It is a convenience function that internally calls [hkdf.Extract](#func-extract) followed by [hkdf.Expand](#func-expand), and is subject to the same requirements.",
			},
		},
	},
	{
		Import: "crypto/hmac",
		Doc:    "Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) as defined in U.S. Federal Information Processing Standards Publication 198.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "Equal",
				Signature: "func hmac.Equal(mac1, mac2 []byte) bool",
				Doc: "Equal compares two MACs for equality without leaking timing information.\n" +
					"\n" +
					"This function does not implement any cryptographic algorithm, therefore out of FIPS scope.",
			},
			{
				Kind:      "func",
				Name:      "New",
				Signature: "func hmac.New(h func() hash.Hash, key []byte) hash.Hash",
				Doc:       "New returns a new HMAC hash using the given hash.Hash type and key.",
				Requirements: &ugRequirements{
					Items: []string{
						"`h` must be one of the following functions: sha1.New, sha224.New, sha256.New, sha384.New, or sha512.New.",
						"The CNG backend does not support sha224.New. ",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						{
							Name: "OpenSSL 1.x",
							Body: "The hmac is generated using [HMAC_CTX_new] and [HMAC_Init_ex].\n" +
								"\n" +
								"The hash.Hash methods are implemented as follows:\n" +
								"\n" +
								"- `Write` using [HMAC_Update].\n" +
								"- `Sum` using [HMAC_Final].\n" +
								"- `Reset` using [HMAC_Init_ex].",
						},
						{
							Name: "OpenSSL 3.x",
							Body: "The hmac is generated using [EVP_MAC_CTX_new] and [EVP_MAC_init].\n" +
								"\n" +
								"The hash.Hash methods are implemented as follows:\n" +
								"\n" +
								"- `Write` using [EVP_MAC_update].\n" +
								"- `Sum` using [EVP_MAC_final].\n" +
								"- `Reset` using [EVP_MAC_init].",
						},
						cng("The hmac is generated using [BCryptCreateHash] with the `BCRYPT_ALG_HANDLE_HMAC_FLAG` flag.\n" +
							"\n" +
							"The [algorithm identifier] depends on the value of `h`:\n" +
							"\n" +
							"- If `h == sha1.New` then algorithm is `BCRYPT_SHA1_ALGORITHM`.\n" +
							"- If `h == sha256.New` then algorithm is `BCRYPT_SHA256_ALGORITHM`.\n" +
							"- If `h == sha384.New` then algorithm is `BCRYPT_SHA384_ALGORITHM`.\n" +
							"- If `h == sha512.New` then algorithm is `BCRYPT_SHA512_ALGORITHM`.\n" +
							"\n" +
							"The hash.Hash methods are implemented as follows:\n" +
							"\n" +
							"- `Write` using [BCryptHashData].\n" +
							"- `Sum` using [BCryptFinishHash].\n" +
							"- `Reset` using [BCryptDestroyHash] and [BCryptCreateHash]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/md5",
		Doc: "Package md5 implements the MD5 hash algorithm as defined in RFC 1321.\n" +
			"\n" +
			"MD5 is cryptographically broken and should not be used for secure applications.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "New",
				Signature: "func md5.New() hash.Hash",
				Doc:       "New returns a new hash.Hash computing the MD5 checksum.",
				Impl:      hashImpl("EVP_md5", "BCRYPT_MD5_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "Sum",
				Signature: "func md5.Sum(data []byte) [15]byte",
				Doc:       sumDoc("Sum", "MD5", "md5.New()"),
			},
		},
	},
	{
		Import: "crypto/mldsa",
		Doc: "Package mldsa implements the post-quantum ML-DSA signature scheme as defined in FIPS 204.\n" +
			"\n" +
			"The parameter set is selected with one of `mldsa.MLDSA44()`, `mldsa.MLDSA65()`, or `mldsa.MLDSA87()`.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "GenerateKey",
				Signature: "func mldsa.GenerateKey(params mldsa.Parameters) (*mldsa.PrivateKey, error)",
				Doc:       "GenerateKey generates a new random ML-DSA private key for the given parameter set.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`priv` is a wrapper around an [EVP_PKEY] generated using [EVP_PKEY_keygen] with the `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87` key type."),
						cng("`priv` is generated using [BCryptGenerateKeyPair] with the `BCRYPT_MLDSA_ALGORITHM` [algorithm identifier] and the parameter set name (`44`, `65`, or `87`) set via the `BCRYPT_PARAMETER_SET_NAME` property."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewPrivateKey",
				Signature: "func mldsa.NewPrivateKey(params mldsa.Parameters, seed []byte) (*mldsa.PrivateKey, error)",
				Doc:       "NewPrivateKey decodes an ML-DSA private key from the given `seed`, which must be exactly `mldsa.PrivateKeySize` bytes long. The key is reconstructed from the seed using the same backend primitives as [mldsa.GenerateKey](#func-generatekey-2).",
			},
			{
				Kind:      "func",
				Name:      "NewPublicKey",
				Signature: "func mldsa.NewPublicKey(params mldsa.Parameters, encoding []byte) (*mldsa.PublicKey, error)",
				Doc:       "NewPublicKey decodes an ML-DSA public key from the given `encoding`, whose length must match `params.PublicKeySize()`.",
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.Sign",
				Signature: "func (sk *mldsa.PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)",
				Doc:       "Sign returns a signature of `message` using `sk`. The `io.Reader` argument is ignored.",
				Requirements: &ugRequirements{
					Items: []string{
						"If `opts` is nil or `opts.HashFunc()` returns zero, `message` is signed directly.",
						"If `opts.HashFunc()` returns `crypto.MLDSAMu`, `message` must be a pre-hashed μ message representative (external-mu, as defined in RFC 9881).",
						"An optional context string can be supplied through `*mldsa.Options`.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The message is signed using [EVP_PKEY_sign]."),
						cng("The message is signed using [BCryptSignHash]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.SignDeterministic",
				Signature: "func (sk *mldsa.PrivateKey) SignDeterministic(message []byte, opts crypto.SignerOpts) (signature []byte, err error)",
				Doc:       "SignDeterministic behaves as [mldsa.PrivateKey.Sign](#func-privatekeysign-2) but produces a deterministic signature. It is subject to the same requirements.",
			},
			{
				Kind:      "func",
				Name:      "Verify",
				Signature: "func mldsa.Verify(pk *mldsa.PublicKey, message []byte, signature []byte, opts *mldsa.Options) error",
				Doc:       "Verify reports whether `signature` is a valid signature of `message` by `pk`. A valid signature is indicated by returning a nil error.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The signature is verified using [EVP_PKEY_verify]."),
						cng("The signature is verified using [BCryptVerifySignature]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/mlkem",
		Doc: "Package mlkem implements the post-quantum ML-KEM key encapsulation method as defined in FIPS 203.\n" +
			"\n" +
			"ML-KEM-768 and ML-KEM-1024 are supported by all backends.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "GenerateKey768",
				Signature: "func mlkem.GenerateKey768() (*mlkem.DecapsulationKey768, error)",
				Doc:       "GenerateKey768 generates a new ML-KEM-768 decapsulation key. The corresponding encapsulation key is obtained with the `EncapsulationKey` method.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The key is a wrapper around an [EVP_PKEY] generated using [EVP_PKEY_keygen] with the `ML-KEM-768` key type."),
						cng("The key is generated using [BCryptGenerateKeyPair] with the `BCRYPT_MLKEM_ALGORITHM` [algorithm identifier] and the `768` parameter set name set via the `BCRYPT_PARAMETER_SET_NAME` property."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "GenerateKey1024",
				Signature: "func mlkem.GenerateKey1024() (*mlkem.DecapsulationKey1024, error)",
				Doc: "GenerateKey1024 generates a new ML-KEM-1024 decapsulation key. It behaves as [mlkem.GenerateKey768](#func-generatekey768) but uses the `ML-KEM-1024` key type (OpenSSL) or the `1024` parameter set name (CNG).\n" +
					"\n" +
					"Decapsulation keys can also be reconstructed from a seed using `mlkem.NewDecapsulationKey768` and `mlkem.NewDecapsulationKey1024`, and encapsulation keys can be decoded with `mlkem.NewEncapsulationKey768` and `mlkem.NewEncapsulationKey1024`.",
			},
			{
				Kind:      "func",
				Name:      "EncapsulationKey768.Encapsulate",
				Signature: "func (ek *mlkem.EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte)",
				Doc:       "Encapsulate generates a shared key and an associated ciphertext from the encapsulation key. The same shared key is recovered by the holder of the decapsulation key via [mlkem.DecapsulationKey768.Decapsulate](#func-decapsulationkey768decapsulate). The shared key must be kept secret.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The shared key and ciphertext are generated using [EVP_PKEY_encapsulate]."),
						cng("The shared key and ciphertext are generated using the CNG ML-KEM encapsulation operation."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "DecapsulationKey768.Decapsulate",
				Signature: "func (dk *mlkem.DecapsulationKey768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error)",
				Doc:       "Decapsulate recovers the shared key from `ciphertext` using the decapsulation key. The ML-KEM-1024 keys expose analogous `Encapsulate` and `Decapsulate` methods.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The shared key is recovered using [EVP_PKEY_decapsulate]."),
						cng("The shared key is recovered using the CNG ML-KEM decapsulation operation."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/pbkdf2",
		Doc:    "Package pbkdf2 implements the key derivation function PBKDF2 as defined in RFC 8018 (PKCS #5 v2.1).",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "Key",
				Signature: "func pbkdf2.Key[H hash.Hash](h func() H, password string, salt []byte, iter, keyLength int) ([]byte, error)",
				Doc:       "Key derives a key of `keyLength` bytes from `password` and `salt` by applying the pseudorandom function `iter` times.",
				Requirements: &ugRequirements{
					Items: []string{
						"`h` must return a hash supported by the crypto backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("On OpenSSL 1.x the key is derived using [PKCS5_PBKDF2_HMAC].\n" +
							"On OpenSSL 3.x the key is derived using [EVP_KDF_derive] with the `PBKDF2` KDF."),
						cng("The key is derived using [BCryptKeyDerivation] with the `BCRYPT_PBKDF2_ALGORITHM` [algorithm identifier], setting the iteration count, hash algorithm, and salt through key derivation parameters."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/rand",
		Doc:    "Package rand implements a cryptographically secure random number generator.",
		Entries: []ugEntry{
			{
				Kind:      "var",
				Name:      "Reader",
				Anchor:    "pkg-variables",
				Signature: "var Reader io.Reader",
				Doc: "Reader is a global, shared instance of a cryptographically secure random number generator.\n" +
					"\n" +
					"It is assigned to boring.RandReader in the crypto/rand init function.",
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`rand.Reader` implements `io.Reader` using [RAND_bytes]"),
						cng("`rand.Reader` implements `io.Reader` using [BCryptGenRandom]"),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Int",
				Signature: "func rand.Int(rand io.Reader, max *big.Int) (n *big.Int, err error)",
				Doc:       "Int returns a uniform random value in [0, max). It panics if max <= 0.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Prime",
				Signature: "func Prime(rand io.Reader, bits int) (p *big.Int, err error)",
				Doc:       "Prime returns a number of the given bit length that is prime with high probability.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Read",
				Signature: "func Read(b []byte) (n int, err error)",
				Doc:       "Read is a helper function that calls rand.Reader.Read using io.ReadFull.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand.Reader` must be boring.RandReader. This invariant is normally met as `rand.Reader` is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
			},
		},
	},
	{
		Import: "crypto/rc4",
		Doc:    "Package rc4 implements RC4 encryption, as defined in Bruce Schneier's Applied Cryptography.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "NewCipher",
				Signature: "func rc4.NewCipher() rc4.Cipher",
				Doc:       "NewCipher creates and returns a new Cipher. The key argument should be the RC4 key, at least 1 byte and at most 256 bytes.",
				Requirements: &ugRequirements{
					Text: "Some OpenSSL distributions don't implement RC4, e.g., OpenSSL 1.x compiled with `-DOPENSSL_NO_RC4` and OpenSSL 3.x that can't load the legacy provider.\n" +
						"In those cases, `rc4.NewCipher()` will fall back to standard Go crypto.",
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The cipher is generated using [EVP_CIPHER_CTX_new] and [EVP_CipherInit_ex] with the cipher type [EVP_rc4].\n" +
							"\n" +
							"The rc4.Cipher methods are implemented as follows:\n" +
							"\n" +
							"- `Reset` using [EVP_CIPHER_CTX_free].\n" +
							"- `XORKeyStream` using [EVP_EncryptUpdate]."),
						cng("The cipher is generated using [BCryptGenerateSymmetricKey] using the `BCRYPT_RC4_ALGORITHM` mode.\n" +
							"\n" +
							"The rc4.Cipher methods are implemented as follows:\n" +
							"\n" +
							"- `Reset` using [BCryptDestroyKey].\n" +
							"- `XORKeyStream` using [BCryptEncrypt]."),
					},
				},
			},
		},
	},
	{
		Import: "crypto/sha1",
		Doc: "Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.\n" +
			"\n" +
			"SHA-1 is an approved FIPS 140-2 hash algorithm although it is cryptographically broken and should not be used for secure applications.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "New",
				Signature: "func sha1.New() hash.Hash",
				Doc:       "New returns a new hash.Hash computing the SHA1 checksum.",
				Impl:      hashImpl("EVP_sha1", "BCRYPT_SHA1_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "Sum",
				Signature: "func sha1.Sum(data []byte) [20]byte",
				Doc:       sumDoc("Sum", "SHA-1", "sha1.New()"),
			},
		},
	},
	{
		Import: "crypto/sha256",
		Doc:    "Package sha256 implements the SHA224 and SHA256 hash algorithms as defined in FIPS 180-4.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "New",
				Signature: "func sha256.New() hash.Hash",
				Doc:       "New returns a new hash.Hash computing the SHA256 checksum.",
				Impl:      hashImpl("EVP_sha256", "BCRYPT_SHA256_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "New224",
				Signature: "func sha256.New224() hash.Hash",
				Doc:       "New224 returns a new hash.Hash computing the SHA224 checksum.",
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
					},
				},
				Impl: hashImpl("EVP_sha224", ""),
			},
			{
				Kind:      "func",
				Name:      "Sum224",
				Signature: "func sha256.Sum224(data []byte) [24]byte",
				Doc:       sumDoc("Sum224", "SHA224", "sha224.New()"),
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
					},
				},
			},
			{
				Kind:      "func",
				Name:      "Sum256",
				Signature: "func sha256.Sum256(data []byte) [32]byte",
				Doc:       sumDoc("Sum256", "SHA256", "sha256.New()"),
			},
		},
	},
	{
		Import: "crypto/sha3",
		Doc: "Package sha3 implements the SHA-3 hash functions and the SHAKE and cSHAKE extendable-output functions (XOFs) as defined in FIPS 202.\n" +
			"\n" +
			"The `sha3.Sum224`, `sha3.Sum256`, `sha3.Sum384`, and `sha3.Sum512` one-shot helpers internally use the corresponding `New*` constructor, and `sha3.SumSHAKE128` and `sha3.SumSHAKE256` internally use the corresponding SHAKE constructor.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "New224",
				Signature: "func sha3.New224() *sha3.SHA3",
				Doc:       "New224 returns a new hash.Hash computing the SHA3-224 checksum.",
				Requirements: &ugRequirements{
					Items: []string{
						"The CNG backend does not implement this function.",
					},
				},
				Impl: hashImpl("EVP_sha3_224", ""),
			},
			{
				Kind:      "func",
				Name:      "New256",
				Signature: "func sha3.New256() *sha3.SHA3",
				Doc:       "New256 returns a new hash.Hash computing the SHA3-256 checksum.",
				Impl:      hashImpl("EVP_sha3_256", "BCRYPT_SHA3_256_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "New384",
				Signature: "func sha3.New384() *sha3.SHA3",
				Doc:       "New384 returns a new hash.Hash computing the SHA3-384 checksum.",
				Impl:      hashImpl("EVP_sha3_384", "BCRYPT_SHA3_384_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "New512",
				Signature: "func sha3.New512() *sha3.SHA3",
				Doc:       "New512 returns a new hash.Hash computing the SHA3-512 checksum.",
				Impl:      hashImpl("EVP_sha3_512", "BCRYPT_SHA3_512_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "NewSHAKE128",
				Signature: "func sha3.NewSHAKE128() *sha3.SHAKE",
				Doc:       "NewSHAKE128 returns a new SHAKE128 XOF.",
				Requirements: &ugRequirements{
					Items: []string{
						"The OpenSSL backend requires OpenSSL 3.3 or higher.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("The XOF is generated using [EVP_MD_CTX_new] and [EVP_DigestInit_ex] with the SHAKE128 algorithm.\n" +
							"\n" +
							"The XOF methods are implemented as follows:\n" +
							"\n" +
							"- `Write` using [EVP_DigestUpdate].\n" +
							"- `Read` using [EVP_DigestSqueeze]."),
						cng("The XOF is generated using [BCryptCreateHash] with the `BCRYPT_CSHAKE128_ALGORITHM` [algorithm identifier].\n" +
							"\n" +
							"The XOF methods are implemented as follows:\n" +
							"\n" +
							"- `Write` using [BCryptHashData].\n" +
							"- `Read` using [BCryptFinishHash]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewSHAKE256",
				Signature: "func sha3.NewSHAKE256() *sha3.SHAKE",
				Doc: "NewSHAKE256 returns a new SHAKE256 XOF.\n" +
					"It is implemented as [sha3.NewSHAKE128](#func-newshake128) but with the SHAKE256 algorithm (OpenSSL) or the `BCRYPT_CSHAKE256_ALGORITHM` [algorithm identifier] (CNG). It is subject to the same requirements.",
			},
			{
				Kind:      "func",
				Name:      "NewCSHAKE128",
				Signature: "func sha3.NewCSHAKE128(N, S []byte) *sha3.SHAKE",
				Doc:       "NewCSHAKE128 returns a new cSHAKE128 XOF, customized with the function-name string `N` and the customization string `S`. When both `N` and `S` are empty it is equivalent to [sha3.NewSHAKE128](#func-newshake128).",
				Requirements: &ugRequirements{
					Items: []string{
						"The OpenSSL backend does not implement this function.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						cng("The XOF is generated using [BCryptCreateHash] with the `BCRYPT_CSHAKE128_ALGORITHM` [algorithm identifier]. The function-name string `N` and the customization string `S` are set with the `BCRYPT_FUNCTION_NAME_STRING` and `BCRYPT_CUSTOMIZATION_STRING` properties.\n" +
							"\n" +
							"The XOF methods are implemented as follows:\n" +
							"\n" +
							"- `Write` using [BCryptHashData].\n" +
							"- `Read` using [BCryptFinishHash]."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "NewCSHAKE256",
				Signature: "func sha3.NewCSHAKE256(N, S []byte) *sha3.SHAKE",
				Doc: "NewCSHAKE256 returns a new cSHAKE256 XOF.\n" +
					"It is implemented as [sha3.NewCSHAKE128](#func-newcshake128) but with the `BCRYPT_CSHAKE256_ALGORITHM` [algorithm identifier], and is subject to the same requirements.",
			},
		},
	},
	{
		Import: "crypto/sha512",
		Doc:    "Package sha512 implements the SHA-384, SHA-512, SHA-512/224, and SHA-512/256 hash algorithms as defined in FIPS 180-4.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "New",
				Signature: "func sha512.New() hash.Hash",
				Doc:       "New returns a new hash.Hash computing the SHA-512 checksum.",
				Impl:      hashImpl("EVP_sha512", "BCRYPT_SHA512_ALGORITHM"),
			},
			{
				Kind:      "func",
				Name:      "New384",
				Signature: "func sha512.New384() hash.Hash",
				Doc:       "New384 returns a new hash.Hash computing the SHA-384 checksum.",
				Impl:      hashImpl("EVP_sha384", "BCRYPT_SHA384_ALGORITHM"),
			},
			notImplementedFunc("sha512.New512_224"),
			notImplementedFunc("sha512.New512_256"),
			{
				Kind:      "func",
				Name:      "Sum384",
				Signature: "func sha512.Sum384(data []byte) [48]byte",
				Doc:       sumDoc("Sum384", "SHA384", "sha512.New384()"),
			},
			{
				Kind:      "func",
				Name:      "Sum512",
				Signature: "func sha512.Sum512(data []byte) [64]byte",
				Doc:       sumDoc("Sum512", "SHA512", "sha512.New()"),
			},
			notImplementedFunc("sha512.Sum512_224"),
			notImplementedFunc("sha512.Sum512_256"),
		},
	},
	{
		Import: "crypto/rsa",
		Doc:    "Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.",
		Entries: []ugEntry{
			{
				Kind:      "func",
				Name:      "DecryptOAEP",
				Signature: "func rsa.DecryptOAEP(h hash.Hash, rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error)",
				Doc:       "DecryptOAEP decrypts ciphertext using RSA-OAEP.",
				Requirements: &ugRequirements{
					Items: []string{
						"`h` must be the result of one of the following functions: sha1.New(), sha224.New(), sha256.New(), sha384.New(), or sha512.New().",
						"The CNG backend does not support sha224.New().",
						"`rand` is not used. Blinding, if implemented, is delegated to crypto backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_OAEP_PADDING` pad mode."),
						cng("`ciphertext` is decrypted using [BCryptDecrypt] with [BCRYPT_OAEP_PADDING_INFO] padding information and `BCRYPT_PAD_OAEP` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "DecryptPKCS1v15",
				Signature: "func rsa.DecryptPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error)",
				Doc:       "DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` is not used. Blinding, if implemented, is delegated to crypto backend.",
						"`priv.Primes` length must be 2 when using the CNG backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_PADDING` pad mode."),
						cng("`ciphertext` is decrypted using [BCryptDecrypt] with `BCRYPT_PAD_PKCS1` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "DecryptPKCS1v15SessionKey",
				Signature: "func rsa.DecryptPKCS1v15SessionKey(rand io.Reader, priv *PrivateKey, ciphertext []byte, key []byte) error",
				Doc:       "DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding scheme from PKCS #1 v1.5.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` is not used. Blinding, if implemented, is delegated to crypto backend.",
						"`priv.Primes` length must be 2 when using the CNG backend.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`ciphertext` is decrypted using [EVP_PKEY_decrypt] with `RSA_PKCS1_PADDING` pad mode and copied into `key`."),
						cng("`ciphertext` is decrypted using [BCryptDecrypt] with `BCRYPT_PAD_PKCS1` pad mode and copied into `key`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "EncryptPKCS1v15",
				Signature: "func rsa.EncryptPKCS1v15(rand io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error)",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader, else SignPSS will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`msg` is encrypted using [EVP_PKEY_encrypt] with `RSA_PKCS1_PADDING` pad mode."),
						cng("`msg` is encrypted using [BCryptEncrypt] with `BCRYPT_PAD_PKCS1` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "SignPKCS1v15",
				Signature: "func rsa.SignPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error)",
				Doc:       "SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` is not used. Blinding, if implemented, is delegated to crypto backend.",
						"`priv.Primes` length must be 2 when using the CNG backend.",
						"`hash` must be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, or crypto.SHA512. Else SignPKCS1v15 will fail.",
						"The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.",
						"`hashed` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`hashed` is signed using [EVP_PKEY_sign] with `RSA_PKCS1_PADDING`."),
						cng("`hashed` is signed using [BCryptSignHash] with [BCRYPT_PKCS1_PADDING_INFO] padding information and `BCRYPT_PAD_PKCS1` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "SignPSS",
				Signature: "func rsa.SignPSS(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error)",
				Doc:       "SignPSS calculates the signature of digest using PSS.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader, else SignPSS will panic. `crypto/rand.Reader` normally meets this invariant, as it is assigned to boring.RandReader in the crypto/rand init function.",
						"`priv.Primes` length must be 2 when using the CNG backend.",
						"`hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, or crypto.SHA512. Else SignPSS will fail.",
						"The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.",
						"`digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
						"`opts` can be nil.",
						"`opts.SaltLength` can either be a number of bytes, or one of the following constants: rsa.PSSSaltLengthAuto and rsa.PSSSaltLengthEqualsHash.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`digest` is signed using [EVP_PKEY_sign] with `RSA_PKCS1_PSS_PADDING` pad mode."),
						cng("`digest` is signed using [BCryptSignHash] with [BCRYPT_PSS_PADDING_INFO] padding information and `BCRYPT_PAD_PSS` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "VerifyPKCS1v15",
				Signature: "func rsa.VerifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error",
				Doc:       "VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.",
				Requirements: &ugRequirements{
					Items: []string{
						"`hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, or crypto.SHA512. Else SignPSS will fail.",
						"The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.",
						"`hashed` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`sig` is verified using [EVP_PKEY_verify] with `RSA_PKCS1_PADDING` pad mode."),
						cng("`sig` is verified using [BCryptVerifySignature] with [BCRYPT_PKCS1_PADDING_INFO] padding information and `BCRYPT_PAD_PKCS1` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "VerifyPSS",
				Signature: "func rsa.VerifyPSS(pub *rsa.PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error",
				Doc:       "VerifyPSS verifies a PSS signature.",
				Requirements: &ugRequirements{
					Items: []string{
						"`hash` can be one of the following values: crypto.MD5, crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, or crypto.SHA512. Else VerifyPSS will fail.",
						"The CNG backend does not support crypto.MD5SHA1 nor crypto.SHA224.",
						"`digest` must be the result of hashing a message using a FIPS compliant hashing algorithm.",
						"`opts` can be nil.",
						"`opts.SaltLength` can either be a number of bytes, or one of the following constants: rsa.PSSSaltLengthAuto and rsa.PSSSaltLengthEqualsHash.",
						"The CNG backend does not support nil `opts` nor rsa.PSSSaltLengthAuto.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`sig` is verified using [EVP_PKEY_verify] with `RSA_PKCS1_PSS_PADDING` pad mode."),
						cng("`sig` is verified using [BCryptVerifySignature] with [BCRYPT_PSS_PADDING_INFO] padding information and `BCRYPT_PAD_PSS` pad mode."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "GenerateKey",
				Signature: "func rsa.GenerateKey(rand io.Reader, bits int) (priv *rsa.PrivateKey, err error)",
				Doc:       "GenerateKey generates a public and private key pair.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
						"`bits` must be either 2048 or 3072.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`priv` is a wrapper around [EVP_PKEY] generated using [EVP_PKEY_keygen]."),
						cng("`priv` is generated using [BCryptGenerateKeyPair] with the [algorithm identifier] `BCRYPT_RSA_ALGORITHM`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "GenerateMultiPrimeKey",
				Signature: "func rsa.GenerateMultiPrimeKey(rand io.Reader, nprimes int, bits int) (priv *rsa.PrivateKey, err error)",
				Doc:       "GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit size.",
				Requirements: &ugRequirements{
					Items: []string{
						"`rand` must be boring.RandReader. `crypto/rand.Reader` normally meets this invariant as it is assigned to boring.RandReader in the crypto/rand init function.",
						"`nprimes` must be 2. ",
						"`bits` must be either 2048 or 3072.",
					},
				},
				Impl: &ugImpl{
					Backends: []ugBackend{
						openssl("`priv` is a wrapper around [EVP_PKEY] generated using [EVP_PKEY_keygen]."),
						cng("`priv` is generated using [BCryptGenerateKeyPair] with the [algorithm identifier] `BCRYPT_RSA_ALGORITHM`."),
					},
				},
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.Decrypt",
				Signature: "func (priv *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)",
				Doc: "Decrypt decrypts `ciphertext` with `priv`.\n" +
					"\n" +
					"The decrypt function depends on `opts`:\n" +
					"\n" +
					"- If `opts` is nil, it calls [rsa.DecryptPKCS1v15](#func-decryptpkcs1v15)`(rand, priv, ciphertext)`.\n" +
					"- If `opts` type is `*rsa.OAEPOptions`, it calls [rsa.DecryptOAEP](#func-decryptoaep)`(opts.Hash.New(), rand, priv, ciphertext, opts.Label)`.\n" +
					"- If `opts` type is `*rsa.OAEPOptions` and `ops.Hash` is different than `opts.MGFHash`, it falls back to standard Go crypto.\n" +
					"- If `opts` type is `*rsa.PKCS1v15DecryptOptions` and `opts.SessionKeyLen > 0`, it calls [rsa.DecryptPKCS1v15SessionKey](#func-decryptpkcs1v15sessionkey)`(rand, priv, ciphertext, plaintext)` with a random `plaintext`.\n" +
					"- If `opts` type is `*rsa.PKCS1v15DecryptOptions` and `opts.SessionKeyLen == 0`, it calls [rsa.DecryptPKCS1v15](#func-decryptpkcs1v15)`(rand, priv, ciphertext)`.\n" +
					"- Else it returns an error.\n" +
					"\n" +
					"Each case may impose additional parameter requirements. After determining which case applies, check the linked function to find the additional restrictions.",
			},
			{
				Kind:      "func",
				Name:      "PrivateKey.Sign",
				Signature: "func (priv *rsa.PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)",
				Doc: "Sign signs `digest` with `priv`.\n" +
					"\n" +
					"The sign function depends on `opts`:\n" +
					"\n" +
					"- If `opts` type is `*rsa.PSSOptions`, it calls [rsa.SignPSS](#func-signpss)`(rand, priv, pssOpts.Hash, digest, opts)`\n" +
					"- Else it calls [rsa.SignPKCS1v15](#func-signpkcs1v15)`(rand, priv, opts.HashFunc(), digest)`.\n" +
					"\n" +
					"Each case may impose additional parameter requirements. After determining which case applies, check the linked function to find the additional restrictions.",
			},
		},
	},
	{
		Import: "crypto/subtle",
		Doc:    "Does not contain crypto primitives, out of FIPS scope.",
	},
	{
		Import: "crypto/tls",
		Doc: "Package tls partially implements TLS 1.2, as specified in RFC 5246, and TLS 1.3, as specified in RFC 8446.\n" +
			"\n" +
			"Package tls will automatically use FIPS compliant primitives implemented in other crypto packages.\n" +
			"\n" +
			"Since Go 1.22, the Microsoft build of Go runtime automatically enforces that tls only uses FIPS-approved settings when running in FIPS mode.\n" +
			"Prior to Go 1.22, a program using tls must import the `crypto/tls/fipsonly` package to be compliant with these restrictions.\n" +
			"\n" +
			"Since Go 1.26, the Microsoft build of Go applies a set of Microsoft-recommended TLS defaults (for example, preferring AES-256 over AES-128 and enabling ML-KEM-based key exchange groups). This is controlled by the `ms_tlsprofile` GODEBUG setting, which defaults to `ms_tlsprofile=default` and can be set to `ms_tlsprofile=off` to restore the upstream Go defaults. The `ms_tlsx25519` GODEBUG setting (default `ms_tlsx25519=1`) controls whether the X25519 and X25519MLKEM768 groups are enabled by default. These settings affect the default selection only; the FIPS-only restrictions below are always enforced in FIPS mode.\n" +
			"\n" +
			"When using TLS in FIPS-only mode the TLS handshake has the following restrictions:\n" +
			"\n" +
			"- TLS versions:\n" +
			"  - `tls.VersionTLS12`\n" +
			"  - `tls.VersionTLS13`\n" +
			"- Key exchange groups:\n" +
			"  - `tls.CurveP256`\n" +
			"  - `tls.CurveP384`\n" +
			"  - `tls.CurveP521`\n" +
			"  - `tls.X25519MLKEM768`\n" +
			"  - `tls.SecP256r1MLKEM768`\n" +
			"  - `tls.SecP384r1MLKEM1024`\n" +
			"  - `tls.MLKEM1024`\n" +
			"\n" +
			"  The standalone `tls.X25519` group is not used in FIPS mode; only the ML-KEM-based hybrid and pure groups above (whose security relies on the FIPS-approved ML-KEM component) and the NIST curves are used. The ML-KEM groups are only offered when supported by the crypto backend.\n" +
			"- Cipher suites for TLS 1.2:\n" +
			"  - `tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`\n" +
			"  - `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`\n" +
			"  - `tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`\n" +
			"  - `tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`\n" +
			"  - `tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`\n" +
			"  - `tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`\n" +
			"- Cipher suites for TLS 1.3:\n" +
			"  - `tls.TLS_AES_256_GCM_SHA384`\n" +
			"  - `tls.TLS_AES_128_GCM_SHA256`\n" +
			"\n" +
			"  The ChaCha20-Poly1305 cipher suites (such as `tls.TLS_CHACHA20_POLY1305_SHA256`) are offered by default outside FIPS mode but are not permitted in FIPS-only mode, as ChaCha20-Poly1305 is not a FIPS-approved algorithm.\n" +
			"- x509 certificate public key:\n" +
			"  - `rsa.PublicKey` with a bit length of 2048 or 3072. Bit length of 4096 is still not supported, see [this issue](https://github.com/golang/go/issues/41147) for more info.\n" +
			"  - `ecdsa.PublicKey`  with a supported elliptic curve.\n" +
			"- Signature algorithms:\n" +
			"  - `tls.PSSWithSHA256`\n" +
			"  - `tls.PSSWithSHA384`\n" +
			"  - `tls.PSSWithSHA512`\n" +
			"  - `tls.PKCS1WithSHA256`\n" +
			"  - `tls.ECDSAWithP256AndSHA256`\n" +
			"  - `tls.PKCS1WithSHA384`\n" +
			"  - `tls.ECDSAWithP384AndSHA384`\n" +
			"  - `tls.PKCS1WithSHA512`\n" +
			"  - `tls.ECDSAWithP521AndSHA512`",
	},
}

// userGuideLinkGroups holds the Markdown link-reference definitions rendered at
// the end of the document. Each group is emitted as a block separated by a
// blank line.
var userGuideLinkGroups = [][]ugLink{
	{
		{Name: "EVP_EncryptUpdate", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html"},
		{Name: "EVP_DecryptUpdate", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DecryptUpdate.html"},
		{Name: "RAND_bytes", URL: "https://www.openssl.org/docs/man3.0/man3/RAND_bytes.html"},
		{Name: "EVP_PKEY", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY.html"},
		{Name: "EVP_PKEY_new", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html"},
		{Name: "EVP_PKEY_new_raw_private_key", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new_raw_private_key.html"},
		{Name: "EVP_PKEY_keygen", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_keygen.html"},
		{Name: "EVP_PKEY_sign", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_sign.html"},
		{Name: "EVP_PKEY_verify", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_verify.html"},
		{Name: "EVP_PKEY_encrypt", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html"},
		{Name: "EVP_PKEY_decrypt", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html"},
		{Name: "EVP_PKEY_derive", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_derive.html"},
		{Name: "EVP_MD_CTX_new", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_new.html"},
		{Name: "EVP_DigestUpdate", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestUpdate.html"},
		{Name: "EVP_DigestFinal", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestFinal.html"},
		{Name: "EVP_DigestInit", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit.html"},
		{Name: "EVP_DigestInit_ex", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestInit_ex.html"},
		{Name: "EVP_DigestSign", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestSign.html"},
		{Name: "EVP_DigestVerify", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerify.html"},
		{Name: "EVP_DigestSign", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestSign.html"},
		{Name: "EVP_DigestSignInit", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestSignInit.html"},
		{Name: "EVP_DigestVerifyInit", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DigestVerifyInit.html"},
		{Name: "EVP_EncryptFinal_ex", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_EncryptFinal_ex.html"},
		{Name: "EVP_DecryptFinal_ex", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_DecryptFinal_ex.html"},
		{Name: "EVP_CIPHER_CTX_set_padding", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_padding.html"},
		{Name: "EVP_aes_128_ecb", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ecb.html"},
		{Name: "EVP_aes_192_ecb", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ecb.html"},
		{Name: "EVP_aes_256_ecb", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ecb.html"},
		{Name: "EVP_aes_128_gcm", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_gcm.html"},
		{Name: "EVP_aes_192_gcm", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_gcm.html"},
		{Name: "EVP_aes_256_gcm", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_gcm.html"},
		{Name: "EVP_aes_128_ctr", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_ctr.html"},
		{Name: "EVP_aes_192_ctr", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_ctr.html"},
		{Name: "EVP_aes_256_ctr", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_ctr.html"},
		{Name: "EVP_aes_128_cbc", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_128_cbc.html"},
		{Name: "EVP_aes_192_cbc", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_192_cbc.html"},
		{Name: "EVP_des_ecb", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_des_ecb.html"},
		{Name: "EVP_des_cbc", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_des_cbc.html"},
		{Name: "EVP_des_ede3_ecb", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_des_ede3_ecb.html"},
		{Name: "EVP_des_ede3_cbc", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_des_ede3_cbc.html"},
		{Name: "EVP_aes_256_cbc", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_aes_256_cbc.html"},
		{Name: "EVP_rc4", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_rc4.html"},
		{Name: "EVP_md5", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_md5.html"},
		{Name: "EVP_sha1", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha1.html"},
		{Name: "EVP_sha224", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha224.html"},
		{Name: "EVP_sha256", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha256.html"},
		{Name: "EVP_sha384", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha384.html"},
		{Name: "EVP_sha512", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha512.html"},
		{Name: "EVP_sha3_224", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha3_224.html"},
		{Name: "EVP_sha3_256", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha3_256.html"},
		{Name: "EVP_sha3_384", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha3_384.html"},
		{Name: "EVP_sha3_512", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_sha3_512.html"},
		{Name: "EVP_DigestSqueeze", URL: "https://www.openssl.org/docs/man3.3/man3/EVP_DigestSqueeze.html"},
		{Name: "EVP_KDF_derive", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_KDF_derive.html"},
		{Name: "EVP_PKEY_encapsulate", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encapsulate.html"},
		{Name: "EVP_PKEY_decapsulate", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decapsulate.html"},
		{Name: "PKCS5_PBKDF2_HMAC", URL: "https://www.openssl.org/docs/man3.0/man3/PKCS5_PBKDF2_HMAC.html"},
		{Name: "HMAC_CTX_new", URL: "https://www.openssl.org/docs/man3.0/man3/HMAC_CTX_new.html"},
		{Name: "HMAC_Init_ex", URL: "https://www.openssl.org/docs/man3.0/man3/HMAC_Init_ex.html"},
		{Name: "HMAC_Update", URL: "https://www.openssl.org/docs/man3.0/man3/HMAC_Update.html"},
		{Name: "HMAC_Final", URL: "https://www.openssl.org/docs/man3.0/man3/HMAC_Final.html"},
		{Name: "EVP_MAC_CTX_new", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_MAC_CTX_new.html"},
		{Name: "EVP_MAC_init", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_MAC_init.html"},
		{Name: "EVP_MAC_update", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_MAC_update.html"},
		{Name: "EVP_MAC_final", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_MAC_final.html"},
		{Name: "EVP_CIPHER_CTX_new", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_new.html"},
		{Name: "EVP_CipherInit_ex", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_CipherInit_ex.html"},
		{Name: "EVP_CIPHER_CTX_free", URL: "https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_free.html"},
	},
	{
		{Name: "algorithm identifier", URL: "https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers"},
		{Name: "named elliptic curve", URL: "https://docs.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves"},
		{Name: "BCryptGenRandom", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom"},
		{Name: "BCryptGenerateSymmetricKey", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey"},
		{Name: "BCryptGenerateKeyPair", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair"},
		{Name: "BCryptImportKeyPair", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair"},
		{Name: "BCryptExportKey", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey"},
		{Name: "BCryptEncrypt", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt"},
		{Name: "BCryptDecrypt", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt"},
		{Name: "BCryptSignHash", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash"},
		{Name: "BCryptVerifySignature", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature"},
		{Name: "BCryptCreateHash", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash"},
		{Name: "BCryptHashData", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata"},
		{Name: "BCryptFinishHash", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash"},
		{Name: "BCryptDestroyHash", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash"},
		{Name: "BCryptKeyDerivation", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation"},
		{Name: "BCRYPT_OAEP_PADDING_INFO", URL: "https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_oaep_padding_info"},
		{Name: "BCRYPT_PKCS1_PADDING_INFO", URL: "https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_pkcs1_padding_info"},
		{Name: "BCRYPT_PSS_PADDING_INFO", URL: "https://docs.microsoft.com/en-us/windows/win32/api/Bcrypt/ns-bcrypt-bcrypt_pss_padding_info"},
		{Name: "BCryptDeriveKey", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey"},
		{Name: "BCryptDestroyKey", URL: "https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey"},
	},
}
