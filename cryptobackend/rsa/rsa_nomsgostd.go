// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package rsa

import (
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"reflect"
)

var (
	ErrDecryption     = errors.New("crypto/rsa: decryption error")
	ErrVerification   = errors.New("crypto/rsa: verification error")
	ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA key size")
)

func isDefaultReader(r io.Reader) bool {
	return r != nil && reflect.TypeOf(r).Comparable() && r == rand.Reader
}

func unwrapHash(h hash.Hash) hash.Hash { return h }

func generateFallbackKey(random io.Reader, bits int) (*fipsPrivateKey, error) {
	panic("cryptobackend: not available")
}

func encryptFallback(pub *fipsPublicKey, plaintext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func decryptWithoutCheckFallback(priv *fipsPrivateKey, ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func encryptOAEPFallback(h, mgfHash hash.Hash, random io.Reader, pub *fipsPublicKey, msg, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func decryptOAEPFallback(h, mgfHash hash.Hash, priv *fipsPrivateKey, ciphertext, label []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func signPKCS1v15Fallback(priv *fipsPrivateKey, hash string, hashed []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func verifyPKCS1v15Fallback(pub *fipsPublicKey, hash string, hashed, sig []byte) error {
	panic("cryptobackend: not available")
}

func signPSSFallback(random io.Reader, priv *fipsPrivateKey, h hash.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func pssMaxSaltLength(bits int, h hash.Hash) (int, error) {
	panic("cryptobackend: not available")
}

func verifyPSSFallback(pub *fipsPublicKey, h hash.Hash, hashed, sig []byte, saltLen int) error {
	panic("cryptobackend: not available")
}
