// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package tls13

import "hash"

func SupportsKDF() bool { return false }
func ExpandKDF[H hash.Hash](h func() H, pseudorandomKey []byte, label string, context []byte, keyLen int) ([]byte, error) {
	panic("cryptobackend: not available")
}
