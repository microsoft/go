// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package pbkdf2

import "hash"

func Supports() bool { panic("cryptobackend: not available") }
func Key[H hash.Hash](h func() H, password, salt []byte, iter, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
