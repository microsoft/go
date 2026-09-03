// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run ../internal/hashgen -algorithms 256,224

package sha256

import "github.com/microsoft/go/cryptobackend"

func Sum256(data []byte) (sum [32]byte) {
	if backend.Enabled && Supports256() {
		return sum256(data)
	}
	h := initFallback256()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}

func Sum224(data []byte) (sum [28]byte) {
	if backend.Enabled && Supports224() {
		return sum224(data)
	}
	h := initFallback224()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}
