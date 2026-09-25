// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package gcm

import "crypto/cipher"

func newFallbackTLS12(c cipher.Block) (cipher.AEAD, error) {
	panic("cryptobackend: not available")
}

func newFallbackTLS13(c cipher.Block) (cipher.AEAD, error) {
	panic("cryptobackend: not available")
}
