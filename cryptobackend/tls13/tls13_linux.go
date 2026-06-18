// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package tls13

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func supportsKDF() bool { return openssl.SupportsTLS13KDF() }
func expandKDF[H hash.Hash](h func() H, pseudorandomKey []byte, label string, context []byte, keyLen int) ([]byte, error) {
	return openssl.ExpandTLS13KDF(h, pseudorandomKey, []byte(label), context, keyLen)
}
