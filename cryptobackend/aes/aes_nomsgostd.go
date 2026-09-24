// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package aes

import "crypto/cipher"

func newFallback(key []byte) (cipher.Block, error) {
	panic("cryptobackend: not available")
}
