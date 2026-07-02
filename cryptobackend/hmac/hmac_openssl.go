// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package hmac

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func New[H hash.Hash](h func() H, key []byte) hash.Hash {
	return openssl.NewHMAC(h, key)
}
