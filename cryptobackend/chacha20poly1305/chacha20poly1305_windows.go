// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/fips140"
	"errors"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Supports() bool { return cng.SupportsChaCha20Poly1305() }

func New(key []byte) (cipher.AEAD, error) {
	if fips140.Enforced() {
		return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
	}
	return cng.NewChaCha20Poly1305(key)
}
