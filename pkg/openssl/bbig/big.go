// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a mirror of
// https://github.com/golang/go/blob/36b87f273cc43e21685179dc1664ebb5493d26ae/src/crypto/internal/boring/bbig/big.go.

package bbig

import (
	"math/big"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl"
)

func Enc(b *big.Int) openssl.BigInt {
	if b == nil {
		return nil
	}
	x := b.Bits()
	if len(x) == 0 {
		return openssl.BigInt{}
	}
	return unsafe.Slice((*uint)(&x[0]), len(x))
}

func Dec(b openssl.BigInt) *big.Int {
	if b == nil {
		return nil
	}
	if len(b) == 0 {
		return new(big.Int)
	}
	x := unsafe.Slice((*big.Word)(&b[0]), len(b))
	return new(big.Int).SetBits(x)
}
