// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package ed25519

type backendPrivateKey = *unavailablePrivateKey
type backendPublicKey = *unavailablePublicKey
type unavailablePrivateKey struct{}
type unavailablePublicKey struct{}

func (*unavailablePrivateKey) Bytes() ([]byte, error) { panic("cryptobackend: not available") }
func (*unavailablePublicKey) Bytes() ([]byte, error)  { panic("cryptobackend: not available") }

func Supports() bool                                  { panic("cryptobackend: not available") }
func generateKey() (backendPrivateKey, error)         { panic("cryptobackend: not available") }
func newPrivateKey([]byte) (backendPrivateKey, error) { panic("cryptobackend: not available") }
func newPublicKey([]byte) (backendPublicKey, error)   { panic("cryptobackend: not available") }
func newPrivateKeyFromSeed([]byte) (backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func sign(backendPrivateKey, []byte) ([]byte, error) { panic("cryptobackend: not available") }
func verify(backendPublicKey, []byte, []byte) error  { panic("cryptobackend: not available") }
