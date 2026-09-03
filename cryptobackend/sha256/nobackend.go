// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha256

type backendHash = fipsHash

func Supports256() bool { panic("cryptobackend: not available") }
func Supports224() bool { panic("cryptobackend: not available") }

func newBackendHash256() *backendHash { panic("cryptobackend: not available") }
func newBackendHash224() *backendHash { panic("cryptobackend: not available") }
func sum256(data []byte) [32]byte     { panic("cryptobackend: not available") }
func sum224(data []byte) [28]byte     { panic("cryptobackend: not available") }
