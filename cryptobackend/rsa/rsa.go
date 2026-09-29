// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"errors"
	"hash"
	"io"

	backend "github.com/microsoft/go/cryptobackend"
	"github.com/microsoft/go/cryptobackend/bbig"
)

// GenerateKey generates an RSA key using the native implementation when it can
// honor the requested size and random source, and the Go implementation otherwise.
func GenerateKey(random io.Reader, bits int) (GeneratedKey, error) {
	if backend.Enabled && isDefaultReader(random) && supportsPublicKey(bits) {
		N, E, D, P, Q, Dp, Dq, Qinv, err := generateKey(bits)
		if err != nil {
			return GeneratedKey{}, err
		}
		for _, p := range []BigInt{N, E, D, P, Q, Dp, Dq, Qinv} {
			if len(p) == 0 {
				return GeneratedKey{}, errors.New("crypto/rsa: generated key missing parameters")
			}
		}
		e := bbig.Dec(E)
		e64 := e.Int64()
		if !e.IsInt64() || int64(int(e64)) != e64 {
			return GeneratedKey{}, errors.New("crypto/rsa: generated key exponent too large")
		}
		return GeneratedKey{
			n: bbig.Dec(N).Bytes(), e: int(e64), d: bbig.Dec(D).Bytes(),
			p: bbig.Dec(P).Bytes(), q: bbig.Dec(Q).Bytes(),
			dp: bbig.Dec(Dp).Bytes(), dq: bbig.Dec(Dq).Bytes(), qi: bbig.Dec(Qinv).Bytes(),
		}, nil
	}
	fk, err := generateFallbackKey(random, bits)
	if err != nil {
		return GeneratedKey{}, err
	}
	return GeneratedKey{fips: fk}, nil
}

func EncryptOAEP(h, mgfHash hash.Hash, random io.Reader, pub *PublicKey, msg, label []byte) ([]byte, error) {
	h, mgfHash = unwrapHash(h), unwrapHash(mgfHash)
	if pub.supportsBackend() && isDefaultReader(random) && supportsOAEP(h, mgfHash, label) {
		if len(msg) > pub.Size()-2*h.Size()-2 {
			return nil, ErrMessageTooLong
		}
		k, err := pub.backendKey()
		if err != nil {
			return nil, err
		}
		return encryptOAEP(h, mgfHash, k, msg, label)
	}
	k, err := pub.goKey()
	if err != nil {
		return nil, err
	}
	return encryptOAEPFallback(h, mgfHash, random, k, msg, label)
}

func DecryptOAEP(h, mgfHash hash.Hash, priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	h, mgfHash = unwrapHash(h), unwrapHash(mgfHash)
	if priv.supportsBackend() && supportsOAEP(h, mgfHash, label) {
		if len(ciphertext) > priv.Size() || priv.Size() < 2*h.Size()+2 {
			return nil, ErrDecryption
		}
		k, err := priv.backendKey()
		if err != nil {
			return nil, err
		}
		out, err := decryptOAEP(h, mgfHash, k, ciphertext, label)
		if err != nil {
			return nil, ErrDecryption
		}
		return out, nil
	}
	k, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return decryptOAEPFallback(h, mgfHash, k, ciphertext, label)
}

// Encrypt performs the raw RSA public-key operation.
func Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	// Native raw operations require modulus-sized inputs. Let Go handle
	// other encodings, including short inputs and excess leading zeroes.
	if pub.supportsBackend() && supportsPKCS1v15Encryption() && len(plaintext) == pub.Size() {
		k, err := pub.backendKey()
		if err != nil {
			return nil, err
		}
		return encryptNoPadding(k, plaintext)
	}
	k, err := pub.goKey()
	if err != nil {
		return nil, err
	}
	return encryptFallback(k, plaintext)
}

// DecryptWithoutCheck performs the raw RSA private-key operation. Native
// implementations may additionally check the result for CRT computation errors.
func DecryptWithoutCheck(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if priv.supportsBackend() && supportsPKCS1v15Encryption() && len(ciphertext) == priv.Size() {
		k, err := priv.backendKey()
		if err != nil {
			return nil, err
		}
		out, err := decryptNoPadding(k, ciphertext)
		if err != nil {
			return nil, ErrDecryption
		}
		return out, nil
	}
	k, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return decryptWithoutCheckFallback(k, ciphertext)
}

func SignPKCS1v15(priv *PrivateKey, hash string, hashed []byte) ([]byte, error) {
	if h, ok := hashByName(hash); ok && priv.supportsBackend() && supportsPKCS1v15Signature(h) {
		k, err := priv.backendKey()
		if err != nil {
			return nil, err
		}
		return signPKCS1v15(k, h, hashed)
	}
	k, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return signPKCS1v15Fallback(k, hash, hashed)
}

func VerifyPKCS1v15(pub *PublicKey, hash string, hashed, sig []byte) error {
	if h, ok := hashByName(hash); ok && pub.supportsBackend() && supportsPKCS1v15Signature(h) {
		k, err := pub.backendKey()
		if err != nil {
			return err
		}
		if err := verifyPKCS1v15(k, h, hashed, sig); err != nil {
			return ErrVerification
		}
		return nil
	}
	k, err := pub.goKey()
	if err != nil {
		return err
	}
	return verifyPKCS1v15Fallback(k, hash, hashed, sig)
}

// PSSMaxSaltLength returns the maximum salt length for a key and hash.
func PSSMaxSaltLength(pub *PublicKey, h hash.Hash) (int, error) {
	return pssMaxSaltLength(pub.bitLen(), h)
}

// pssSaltCapacity returns the encoding limit before applying FIPS policy.
// A negative result means the key is too small for the hash.
func pssSaltCapacity(bits, hashSize int) int {
	return (bits-1+7)/8 - 2 - hashSize
}

// SignPSS signs hashed with an explicit, non-negative salt length.
func SignPSS(random io.Reader, priv *PrivateKey, h hash.Hash, hashed []byte, saltLen int) ([]byte, error) {
	h = unwrapHash(h)
	// Bound the explicit salt before Go allocates it or a native API narrows it.
	if saltLen >= 0 && saltLen > pssSaltCapacity(priv.pub.bitLen(), h.Size()) {
		return nil, ErrMessageTooLong
	}
	nativeSalt := saltLen
	if saltLen == h.Size() {
		nativeSalt = -1
	}
	// Native APIs reserve zero for automatic salt selection, so exact zero
	// must use Go. Its positive salt lengths map directly, except that Darwin
	// requires the equals-hash sentinel when that length is requested.
	if hash := nativeHashAlgorithm(h); hash != 0 && saltLen > 0 && priv.supportsBackend() && isDefaultReader(random) && supportsSaltLength(true, nativeSalt) && supportsPSSHash(hash) {
		k, err := priv.backendKey()
		if err != nil {
			return nil, err
		}
		return signPSS(k, hash, hashed, nativeSalt)
	}
	k, err := priv.goKey()
	if err != nil {
		return nil, err
	}
	return signPSSFallback(random, k, h, hashed, saltLen)
}

// VerifyPSS verifies a PSS signature, automatically detecting its salt length.
func VerifyPSS(pub *PublicKey, h hash.Hash, hashed, sig []byte) error {
	return verifyPSSDispatch(pub, h, hashed, sig, -1)
}

// VerifyPSSWithSaltLength verifies a PSS signature with an explicit salt length.
func VerifyPSSWithSaltLength(pub *PublicKey, h hash.Hash, hashed, sig []byte, saltLen int) error {
	if saltLen < 0 {
		return errors.New("crypto/rsa: salt length cannot be negative")
	}
	return verifyPSSDispatch(pub, h, hashed, sig, saltLen)
}

func verifyPSSDispatch(pub *PublicKey, h hash.Hash, hashed, sig []byte, saltLen int) error {
	h = unwrapHash(h)
	// Check without adding saltLen to avoid overflow in Go's padding checks.
	if saltLen >= 0 && saltLen > pssSaltCapacity(pub.bitLen(), h.Size()) {
		return ErrVerification
	}
	nativeSalt := saltLen
	if saltLen == -1 {
		nativeSalt = 0
	} else if saltLen == h.Size() {
		nativeSalt = -1
	}
	if hash := nativeHashAlgorithm(h); hash != 0 && saltLen != 0 && pub.supportsBackend() && supportsSaltLength(false, nativeSalt) && supportsPSSHash(hash) {
		k, err := pub.backendKey()
		if err != nil {
			return err
		}
		if err := verifyPSS(k, hash, hashed, sig, nativeSalt); err != nil {
			return ErrVerification
		}
		return nil
	}
	k, err := pub.goKey()
	if err != nil {
		return err
	}
	return verifyPSSFallback(k, h, hashed, sig, saltLen)
}

func hashByName(name string) (crypto.Hash, bool) {
	if name == "" {
		return 0, true
	}
	for _, h := range []crypto.Hash{crypto.MD4, crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA256,
		crypto.SHA384, crypto.SHA512, crypto.SHA512_224, crypto.SHA512_256, crypto.MD5SHA1,
		crypto.RIPEMD160, crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512} {
		if h.String() == name {
			return h, true
		}
	}
	return 0, false
}

// nativeHashAlgorithm recognizes only concrete native hash implementations.
// Their SHA variants are uniquely identified by digest and block size. MD4 and
// MD5 share both sizes, so leave those algorithms to the Go implementation.
func nativeHashAlgorithm(h hash.Hash) crypto.Hash {
	if !isNativeHash(h) {
		return 0
	}
	switch [2]int{h.Size(), h.BlockSize()} {
	case [2]int{20, 64}:
		return crypto.SHA1
	case [2]int{28, 64}:
		return crypto.SHA224
	case [2]int{32, 64}:
		return crypto.SHA256
	case [2]int{48, 128}:
		return crypto.SHA384
	case [2]int{64, 128}:
		return crypto.SHA512
	case [2]int{28, 128}:
		return crypto.SHA512_224
	case [2]int{32, 128}:
		return crypto.SHA512_256
	case [2]int{28, 144}:
		return crypto.SHA3_224
	case [2]int{32, 136}:
		return crypto.SHA3_256
	case [2]int{48, 104}:
		return crypto.SHA3_384
	case [2]int{64, 72}:
		return crypto.SHA3_512
	}
	return 0
}
