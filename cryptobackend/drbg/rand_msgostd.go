// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package drbg

import fallback "crypto/internal/fips140/drbg"

// DefaultReader is the sentinel type embedded in the default [crypto/rand.Reader].
type DefaultReader = fallback.DefaultReader

func readFallback(b []byte) {
	fallback.Read(b)
}
