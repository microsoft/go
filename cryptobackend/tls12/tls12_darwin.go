// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package tls12

import "hash"

func SupportsPRF() bool { return false }
func PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	panic("cryptobackend: not available")
}
