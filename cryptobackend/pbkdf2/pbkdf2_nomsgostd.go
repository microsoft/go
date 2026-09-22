// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package pbkdf2

import "hash"

func keyFallback[H hash.Hash](h func() H, password string, salt []byte, iter, keyLength int) ([]byte, error) {
	panic("cryptobackend: not available")
}
