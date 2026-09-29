// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package rsa

import (
	"crypto/internal/fips140"
	fallback "crypto/internal/fips140/rsa"
	"crypto/internal/fips140hash"
	"crypto/internal/rand"
	"errors"
	"hash"
	"io"
)

var (
	ErrDecryption     = fallback.ErrDecryption
	ErrVerification   = fallback.ErrVerification
	ErrMessageTooLong = fallback.ErrMessageTooLong
)

func isDefaultReader(r io.Reader) bool { return rand.IsDefaultReader(r) }
func unwrapHash(h hash.Hash) hash.Hash { return fips140hash.Unwrap(h) }

func generateFallbackKey(random io.Reader, bits int) (*fipsPrivateKey, error) {
	return fallback.GenerateKey(random, bits)
}

func encryptFallback(pub *fipsPublicKey, plaintext []byte) ([]byte, error) {
	return fallback.Encrypt(pub, plaintext)
}

func decryptWithoutCheckFallback(priv *fipsPrivateKey, ciphertext []byte) ([]byte, error) {
	return fallback.DecryptWithoutCheck(priv, ciphertext)
}

func encryptOAEPFallback(h, mgfHash hash.Hash, random io.Reader, pub *fipsPublicKey, msg, label []byte) ([]byte, error) {
	return fallback.EncryptOAEP(h, mgfHash, random, pub, msg, label)
}

func decryptOAEPFallback(h, mgfHash hash.Hash, priv *fipsPrivateKey, ciphertext, label []byte) ([]byte, error) {
	return fallback.DecryptOAEP(h, mgfHash, priv, ciphertext, label)
}

func signPKCS1v15Fallback(priv *fipsPrivateKey, hash string, hashed []byte) ([]byte, error) {
	return fallback.SignPKCS1v15(priv, hash, hashed)
}

func verifyPKCS1v15Fallback(pub *fipsPublicKey, hash string, hashed, sig []byte) error {
	return fallback.VerifyPKCS1v15(pub, hash, hashed, sig)
}

func signPSSFallback(random io.Reader, priv *fipsPrivateKey, h hash.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return fallback.SignPSS(random, priv, h, hashed, saltLen)
}

// pssMaxSaltLength mirrors [fallback.PSSMaxSaltLength] without importing a key.
func pssMaxSaltLength(bits int, h hash.Hash) (int, error) {
	// Match bigmod.NewModulus for nil, zero, or unit-magnitude moduli.
	if bits < 2 {
		return 0, errors.New("modulus must be > 1")
	}
	saltLength := pssSaltCapacity(bits, h.Size())
	if saltLength < 0 {
		return 0, ErrMessageTooLong
	}
	// Use the Go module's FIPS mode, as the upstream helper does.
	if fips140.Enabled && saltLength > h.Size() {
		return h.Size(), nil
	}
	return saltLength, nil
}

func verifyPSSFallback(pub *fipsPublicKey, h hash.Hash, hashed, sig []byte, saltLen int) error {
	if saltLen == -1 {
		return fallback.VerifyPSS(pub, h, hashed, sig)
	}
	return fallback.VerifyPSSWithSaltLength(pub, h, hashed, sig, saltLen)
}
