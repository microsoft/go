// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package tls12

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func SupportsPRF() bool { return openssl.SupportsTLS1PRF() }
func PRF(result, secret []byte, label string, seed []byte, h func() hash.Hash) error {
	return openssl.TLS1PRF(result, secret, []byte(label), seed, h)
}
