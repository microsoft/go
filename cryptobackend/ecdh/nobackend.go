// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package ecdh

type PrivateKey struct{}
type PublicKey struct{}

func SupportsCurve(curve string) bool                       { panic("cryptobackend: not available") }
func GenerateKey(curve string) (*PrivateKey, []byte, error) { panic("cryptobackend: not available") }
func NewPrivateKey(curve string, key []byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}
func NewPublicKey(curve string, key []byte) (*PublicKey, error) {
	panic("cryptobackend: not available")
}
func (k *PrivateKey) PublicKey() (*PublicKey, error)        { panic("cryptobackend: not available") }
func (k *PublicKey) Bytes() []byte                          { panic("cryptobackend: not available") }
func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) { panic("cryptobackend: not available") }
