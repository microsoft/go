// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/cipher"

	"github.com/microsoft/go/cryptobackend"
)

// New creates and returns a new [cipher.Block] using an AES key.
// The key must be 16, 24, or 32 bytes long.
func New(key []byte) (cipher.Block, error) {
	if backend.Enabled {
		return newBackendCipher(key)
	}
	return newFallback(key)
}
