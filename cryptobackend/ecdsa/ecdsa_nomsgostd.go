// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package ecdsa

import (
	"hash"
	"io"
)

// Keep the standard-library API visible to source importers without msgostd.
type Point[P any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (P, error)
	ScalarMult(P, []byte) (P, error)
	ScalarBaseMult([]byte) (P, error)
	Add(P, P) P
}

type Curve[P Point[P]] struct{}
type Signature struct{ R, S []byte }
type fipsPublicKey struct{}
type fipsPrivateKey struct{}

func NewPublicKey[P Point[P]](c *Curve[P], Q []byte) (*PublicKey, error) {
	panic("cryptobackend: not available")
}

func NewPrivateKey[P Point[P]](c *Curve[P], D, Q []byte) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func GenerateKey[P Point[P]](c *Curve[P], random io.Reader) (*PrivateKey, error) {
	panic("cryptobackend: not available")
}

func Sign[P Point[P], H hash.Hash](c *Curve[P], h func() H, priv *PrivateKey, random io.Reader, digest []byte) (*Signature, error) {
	panic("cryptobackend: not available")
}

func SignDeterministic[P Point[P], H hash.Hash](c *Curve[P], h func() H, priv *PrivateKey, digest []byte) (*Signature, error) {
	panic("cryptobackend: not available")
}

func Verify[P Point[P]](c *Curve[P], pub *PublicKey, digest []byte, sig *Signature) error {
	panic("cryptobackend: not available")
}
