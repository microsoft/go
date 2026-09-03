// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package sha3

type fallbackSHAKE struct{}

func (*fallbackSHAKE) Write([]byte) (int, error)      { panic("cryptobackend: not available") }
func (*fallbackSHAKE) Read([]byte) (int, error)       { panic("cryptobackend: not available") }
func (*fallbackSHAKE) Reset()                         { panic("cryptobackend: not available") }
func (*fallbackSHAKE) BlockSize() int                 { panic("cryptobackend: not available") }
func (*fallbackSHAKE) MarshalBinary() ([]byte, error) { panic("cryptobackend: not available") }
func (*fallbackSHAKE) AppendBinary([]byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (*fallbackSHAKE) UnmarshalBinary([]byte) error { panic("cryptobackend: not available") }

func newFallbackShake128() *fallbackSHAKE { panic("cryptobackend: not available") }
func newFallbackShake256() *fallbackSHAKE { panic("cryptobackend: not available") }
func newFallbackCShake128([]byte, []byte) *fallbackSHAKE {
	panic("cryptobackend: not available")
}
func newFallbackCShake256([]byte, []byte) *fallbackSHAKE {
	panic("cryptobackend: not available")
}
