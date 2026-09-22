// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pbkdf2

import (
	"errors"
	"hash"

	"github.com/microsoft/go/cryptobackend"
)

// Key derives a key from a password, salt, and iteration count.
func Key[H hash.Hash](h func() H, password string, salt []byte, iter, keyLength int) ([]byte, error) {
	if backend.Enabled && Supports(h()) {
		if keyLength <= 0 {
			return nil, errors.New("pbkdf2: keyLength must be larger than 0")
		}
		return key(h, password, salt, iter, keyLength)
	}
	return keyFallback(h, password, salt, iter, keyLength)
}
