// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package tls12

import (
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func SupportsPRF() bool { return true }
func PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	return cng.TLS1PRF(result, secret, label, seed, h)
}
