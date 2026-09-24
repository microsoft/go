// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20poly1305

import (
	"crypto/cipher"

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
func New(key []byte) (cipher.AEAD, error) {
	if backend.Enabled && Supports() {
		return newBackend(key)
	}
	return fallback.New(key)
}
