// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package ecdh

type backendPrivateKey struct{}
type backendPublicKey struct{}

func SupportsCurve(curve string) bool { panic("cryptobackend: not available") }
func generateKey(curve string) (*backendPrivateKey, []byte, error) {
	panic("cryptobackend: not available")
}
func newPrivateKey(curve string, key []byte) (*backendPrivateKey, error) {
	panic("cryptobackend: not available")
}
func newPublicKey(curve string, key []byte) (*backendPublicKey, error) {
	panic("cryptobackend: not available")
}
func (k *backendPrivateKey) PublicKey() (*backendPublicKey, error) {
	panic("cryptobackend: not available")
}
func (k *backendPublicKey) Bytes() []byte { panic("cryptobackend: not available") }
func ecdh(priv *backendPrivateKey, pub *backendPublicKey) ([]byte, error) {
	panic("cryptobackend: not available")
}
