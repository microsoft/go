// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (linux || freebsd)

package pbkdf2

import (
	"hash"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func Supports() bool { return openssl.SupportsPBKDF2() }
func Key[H hash.Hash](h func() H, password string, salt []byte, iter, keyLength int) ([]byte, error) {
	return openssl.PBKDF2([]byte(password), salt, iter, keyLength, h)
}
