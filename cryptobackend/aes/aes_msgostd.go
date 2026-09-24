// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package aes

import (
	"crypto/cipher"
	fallback "crypto/internal/fips140/aes"
)

func newFallback(key []byte) (cipher.Block, error) {
	block, err := fallback.New(key)
	if err != nil {
		return nil, err
	}
	return block, nil
}
