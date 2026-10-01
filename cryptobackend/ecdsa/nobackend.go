// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package ecdsa

type backendPrivateKey struct{}
type backendPublicKey struct{}

func supportsCurve(curve string) bool { panic("cryptobackend: not available") }
func generateKey(curve string) (X, Y, D []uint, err error) {
	panic("cryptobackend: not available")
}
func newPrivateKey(curve string, Q, D []byte) (*backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func newPublicKey(curve string, Q []byte) (*backendPublicKey, error) {
	panic("cryptobackend: not available")
}
func sign(priv *backendPrivateKey, hash []byte) (*Signature, error) {
	panic("cryptobackend: not available")
}
func verify(pub *backendPublicKey, hash []byte, sig *Signature) error {
	panic("cryptobackend: not available")
}
