// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha512

type backendHash = fipsHash

func Supports512() bool     { panic("cryptobackend: not available") }
func Supports384() bool     { panic("cryptobackend: not available") }
func Supports512_224() bool { panic("cryptobackend: not available") }
func Supports512_256() bool { panic("cryptobackend: not available") }

func newBackendHash512() *backendHash     { panic("cryptobackend: not available") }
func newBackendHash384() *backendHash     { panic("cryptobackend: not available") }
func newBackendHash512_224() *backendHash { panic("cryptobackend: not available") }
func newBackendHash512_256() *backendHash { panic("cryptobackend: not available") }
func sum512(data []byte) [64]byte         { panic("cryptobackend: not available") }
func sum384(data []byte) [48]byte         { panic("cryptobackend: not available") }
func sum512_224(data []byte) [28]byte     { panic("cryptobackend: not available") }
func sum512_256(data []byte) [32]byte     { panic("cryptobackend: not available") }
