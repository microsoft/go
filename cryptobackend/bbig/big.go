// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package bbig

import "math/big"

func Enc(b *big.Int) []uint {
	return nil
}

func Dec(b []uint) *big.Int {
	return nil
}
