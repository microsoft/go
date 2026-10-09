// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cipher provides adapters between crypto/cipher and native crypto providers.
package cipher

// BlockMode matches [crypto/cipher.BlockMode].
type BlockMode interface {
	BlockSize() int
	CryptBlocks(dst, src []byte)
}

// Stream matches [crypto/cipher.Stream].
type Stream interface {
	XORKeyStream(dst, src []byte)
}

// AEAD matches [crypto/cipher.AEAD].
type AEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewFIPSCBCEncrypter returns the provider's FIPS-approved CBC encrypter.
func NewFIPSCBCEncrypter[T BlockMode](block any, iv []byte) (BlockMode, bool) {
	cipher, ok := block.(interface {
		NewFIPSCBCEncrypter(iv []byte) T
	})
	if !ok {
		return nil, false
	}
	return cipher.NewFIPSCBCEncrypter(iv), true
}

// NewFIPSCBCDecrypter returns the provider's FIPS-approved CBC decrypter.
func NewFIPSCBCDecrypter[T BlockMode](block any, iv []byte) (BlockMode, bool) {
	cipher, ok := block.(interface {
		NewFIPSCBCDecrypter(iv []byte) T
	})
	if !ok {
		return nil, false
	}
	return cipher.NewFIPSCBCDecrypter(iv), true
}

// NewFIPSCTR returns the provider's FIPS-approved CTR stream.
func NewFIPSCTR[T Stream](block any, iv []byte) (Stream, bool) {
	cipher, ok := block.(interface {
		NewFIPSCTR(iv []byte) T
	})
	if !ok {
		return nil, false
	}
	return cipher.NewFIPSCTR(iv), true
}

type gcmAble[T AEAD] interface {
	NewGCM(nonceSize, tagSize int) (T, error)
}

// NewGCM returns the provider's GCM.
func NewGCM[T AEAD](block any, nonceSize, tagSize int) (AEAD, bool, error) {
	cipher, ok := block.(gcmAble[T])
	if !ok {
		return nil, false, nil
	}
	gcm, err := cipher.NewGCM(nonceSize, tagSize)
	if err != nil {
		return nil, true, err
	}
	return gcm, true, nil
}
