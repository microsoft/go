// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package gcm

import (
	"crypto/cipher"
	"crypto/internal/fips140/aes"
	fallback "crypto/internal/fips140/aes/gcm"
)

func newFallbackTLS12(c cipher.Block) (cipher.AEAD, error) {
	aead, err := fallback.NewGCMForTLS12(c.(*aes.Block))
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func newFallbackTLS13(c cipher.Block) (cipher.AEAD, error) {
	aead, err := fallback.NewGCMForTLS13(c.(*aes.Block))
	if err != nil {
		return nil, err
	}
	return aead, nil
}
