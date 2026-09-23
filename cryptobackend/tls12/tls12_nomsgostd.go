// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package tls12

import "hash"

func prfFallback[H hash.Hash](h func() H, secret []byte, label string, seed []byte, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
