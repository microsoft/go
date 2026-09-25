// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package drbg

var randReader noRandReader

type noRandReader struct{}

func (noRandReader) Read(b []byte) (int, error) { panic("cryptobackend: not available") }
