// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package sha1

import "hash"

type backendHash struct{}

func (*backendHash) Write([]byte) (int, error)       { panic("cryptobackend: not available") }
func (*backendHash) WriteString(string) (int, error) { panic("cryptobackend: not available") }
func (*backendHash) WriteByte(byte) error            { panic("cryptobackend: not available") }
func (*backendHash) Sum([]byte) []byte               { panic("cryptobackend: not available") }
func (*backendHash) Reset()                          { panic("cryptobackend: not available") }
func (*backendHash) Size() int                       { panic("cryptobackend: not available") }
func (*backendHash) BlockSize() int                  { panic("cryptobackend: not available") }
func (*backendHash) MarshalBinary() ([]byte, error)  { panic("cryptobackend: not available") }
func (*backendHash) AppendBinary([]byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (*backendHash) UnmarshalBinary([]byte) error { panic("cryptobackend: not available") }
func (*backendHash) Clone() (hash.Cloner, error)  { panic("cryptobackend: not available") }

func New() hash.Hash { panic("cryptobackend: not available") }

func Sum(data []byte) [20]byte { panic("cryptobackend: not available") }
