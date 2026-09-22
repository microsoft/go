// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package hkdf

import "hash"

func extractFallback[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}

func expandFallback[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}

func keyFallback[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
