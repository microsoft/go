// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hmac

import (
	"hash"

	"github.com/microsoft/go/cryptobackend"
)

// New returns a new HMAC hash using the given [hash.Hash] type and key.
func New[H hash.Hash](h func() H, key []byte) hash.Hash {
	if backend.Enabled {
		hm := newBackendHMAC(h, key)
		if hm != nil {
			return hm
		}
	}
	return initFallback(h, key)
}
