// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package sha3

import fallback "crypto/internal/fips140/sha3"

type fallbackSHAKE = fallback.SHAKE

func newFallbackShake128() *fallbackSHAKE { return fallback.NewShake128() }
func newFallbackShake256() *fallbackSHAKE { return fallback.NewShake256() }
func newFallbackCShake128(N, S []byte) *fallbackSHAKE {
	return fallback.NewCShake128(N, S)
}
func newFallbackCShake256(N, S []byte) *fallbackSHAKE {
	return fallback.NewCShake256(N, S)
}
