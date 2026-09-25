// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcm

import (
	"crypto/cipher"

	"github.com/microsoft/go/cryptobackend"
)

// NewGCMForTLS12 returns an AEAD that enforces the construction of nonces as
// specified in RFC 5288, Section 3 and RFC 9325, Section 7.2.1.
func NewGCMForTLS12(c cipher.Block) (cipher.AEAD, error) {
	if backend.Enabled {
		return newBackendTLS12(c)
	}
	return newFallbackTLS12(c)
}

// NewGCMForTLS13 returns an AEAD that enforces the construction of nonces as
// specified in RFC 8446, Section 5.3.
func NewGCMForTLS13(c cipher.Block) (cipher.AEAD, error) {
	if backend.Enabled {
		return newBackendTLS13(c)
	}
	return newFallbackTLS13(c)
}
