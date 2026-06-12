// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package pbkdf2

import (
	"hash"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Supports() bool { return true }
func Key[H hash.Hash](h func() H, password string, salt []byte, iter, keyLength int) ([]byte, error) {
	return cng.PBKDF2([]byte(password), salt, iter, keyLength, h)
}
