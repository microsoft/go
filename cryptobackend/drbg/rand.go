// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package drbg

import (
	"io"

	"github.com/microsoft/go/cryptobackend"
)

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) {
	if backend.Enabled {
		if _, err := io.ReadFull(randReader, b); err != nil {
			panic(err)
		}
		return
	}
	readFallback(b)
}
