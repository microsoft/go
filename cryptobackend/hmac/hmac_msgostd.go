// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package hmac

import (
	fallback "crypto/internal/fips140/hmac"
	"hash"
)

func initFallback[H hash.Hash](h func() H, key []byte) hash.Hash {
	return fallback.New(h, key)
}
