// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package drbg

import (
	"io"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func Read(b []byte) {
	if _, err := io.ReadFull(cng.RandReader, b); err != nil {
		panic(err)
	}
}
