// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf

import (
	"hash"

	"github.com/microsoft/go/cryptobackend"
)

// Extract generates a pseudorandom key for use with [Expand] from a secret and salt.
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	if backend.Enabled && Supports(h()) {
		return extract(h, secret, salt)
	}
	return extractFallback(h, secret, salt)
}

// Expand derives a key from a pseudorandom key and context info.
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) ([]byte, error) {
	if backend.Enabled && Supports(h()) {
		return expand(h, pseudorandomKey, info, keyLen)
	}
	return expandFallback(h, pseudorandomKey, info, keyLen)
}

// Key derives a key from a secret, salt, and context info.
func Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) ([]byte, error) {
	if backend.Enabled && Supports(h()) {
		prk, err := extract(h, secret, salt)
		if err != nil {
			return nil, err
		}
		return expand(h, prk, info, keyLen)
	}
	return keyFallback(h, secret, salt, info, keyLen)
}
