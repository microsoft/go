// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package ecdh

import "io"

// Keep the standard-library API visible to source importers without msgostd.
type Point[P any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (P, error)
	ScalarMult(P, []byte) (P, error)
	ScalarBaseMult([]byte) (P, error)
}

type Curve[P Point[P]] struct{}
type fipsPublicKey struct{}
type fipsPrivateKey struct{}

func GenerateKey[P Point[P]](c *Curve[P], random io.Reader) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKey[P Point[P]](c *Curve[P], key []byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func NewPublicKey[P Point[P]](c *Curve[P], key []byte) (*PublicKey, error) {
	panic("cryptobackend: not available")
}

func ECDH[P Point[P]](c *Curve[P], priv *PrivateKey, pub *PublicKey) ([]byte, error) {
	panic("cryptobackend: not available")
}

func GenerateKeyX25519(random io.Reader, scalarBaseMult func(dst, scalar []byte)) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKeyX25519(key []byte, scalarBaseMult func(dst, scalar []byte)) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func NewPublicKeyX25519(key []byte) (*PublicKey, error) {
	panic("cryptobackend: not available")
}

func ECDHX25519(priv *PrivateKey, pub *PublicKey, scalarMult func(dst, scalar, point []byte)) ([]byte, error) {
	panic("cryptobackend: not available")
}
