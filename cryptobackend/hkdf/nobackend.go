// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package hkdf

import "hash"

func Supports() bool { panic("cryptobackend: not available") }
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
