// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/fips140"
	"errors"

	"github.com/microsoft/go/cryptobackend"
	fallback "golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = fallback.KeySize

	// NonceSize is the size of the nonce used by this AEAD, in bytes.
	NonceSize = fallback.NonceSize
)

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
//
// ChaCha20-Poly1305 is not FIPS 140 approved, so New fails in FIPS 140-only
// mode regardless of whether the native backend or the Go fallback is used.
func New(key []byte) (cipher.AEAD, error) {
	if fips140.Enforced() {
		return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
	}
	if backend.Enabled && Supports() {
		return newBackend(key)
	}
	return fallback.New(key)
}
