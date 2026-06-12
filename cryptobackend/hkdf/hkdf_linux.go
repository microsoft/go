// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package hkdf

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func Supports() bool { return openssl.SupportsHKDF() }
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	return openssl.ExtractHKDF(h, secret, salt)
}
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) ([]byte, error) {
	return openssl.ExpandHKDF(h, pseudorandomKey, []byte(info), keyLen)
}
