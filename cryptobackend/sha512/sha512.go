// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run ../internal/hashgen -algorithms 512,384,512_224,512_256

package sha512

import "github.com/microsoft/go/cryptobackend"

func Sum512(data []byte) (sum [64]byte) {
	if backend.Enabled && Supports512() {
		return sum512(data)
	}
	h := initFallback512()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}

func Sum384(data []byte) (sum [48]byte) {
	if backend.Enabled && Supports384() {
		return sum384(data)
	}
	h := initFallback384()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}

func Sum512_224(data []byte) (sum [28]byte) {
	if backend.Enabled && Supports512_224() {
		return sum512_224(data)
	}
	h := initFallback512_224()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}

func Sum512_256(data []byte) (sum [32]byte) {
	if backend.Enabled && Supports512_256() {
		return sum512_256(data)
	}
	h := initFallback512_256()
	h.Write(data)
	h.Sum(sum[:0])
	return sum
}
