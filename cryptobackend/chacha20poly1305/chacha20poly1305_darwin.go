// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package chacha20poly1305

import (
	"crypto/cipher"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func Supports() bool { return true }

func newBackend(key []byte) (cipher.AEAD, error) {
	return xcrypto.NewChaCha20Poly1305(key)
}
