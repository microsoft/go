// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package hkdf

import (
	fallback "crypto/internal/fips140/hkdf"
	"hash"
)

func extractFallback[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	return fallback.Extract(h, secret, salt), nil
}

func expandFallback[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) ([]byte, error) {
	return fallback.Expand(h, pseudorandomKey, info, keyLen), nil
}

func keyFallback[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) ([]byte, error) {
	return fallback.Key(h, secret, salt, info, keyLen), nil
}
