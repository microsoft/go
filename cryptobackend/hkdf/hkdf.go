// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf

import "hash"

func Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) ([]byte, error) {
	prk, err := Extract(h, secret, salt)
	if err != nil {
		return nil, err
	}
	return Expand(h, prk, info, keyLen)
}
