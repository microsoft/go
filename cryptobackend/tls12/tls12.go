// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls12

import (
	"hash"

	"github.com/microsoft/go/cryptobackend"
)

// PRF implements the TLS 1.2 pseudo-random function as defined in RFC 5246, Section 5.
func PRF[H hash.Hash](h func() H, secret []byte, label string, seed []byte, keyLen int) ([]byte, error) {
	if backend.Enabled && SupportsPRF() {
		result := make([]byte, keyLen)
		if err := prf(result, secret, label, seed, h); err != nil {
			return nil, err
		}
		return result, nil
	}
	return prfFallback(h, secret, label, seed, keyLen)
}
