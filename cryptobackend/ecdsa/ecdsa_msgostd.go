// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package ecdsa

import (
	fallback "crypto/internal/fips140/ecdsa"
	"crypto/internal/fips140/nistec"
	"crypto/internal/rand"
	cryptorand "crypto/rand"
	"errors"
	"hash"
	"io"

	backend "github.com/microsoft/go/cryptobackend"
	"github.com/microsoft/go/cryptobackend/bbig"
)

type Point[P any] = fallback.Point[P]
type Curve[P Point[P]] = fallback.Curve[P]
type Signature = fallback.Signature
type fipsPublicKey = fallback.PublicKey
type fipsPrivateKey = fallback.PrivateKey

func P224() *Curve[*nistec.P224Point] { return fallback.P224() }
func P256() *Curve[*nistec.P256Point] { return fallback.P256() }
func P384() *Curve[*nistec.P384Point] { return fallback.P384() }
func P521() *Curve[*nistec.P521Point] { return fallback.P521() }

func isDefaultReader(r io.Reader) bool {
	// SetGlobalRandom replaces the public reader as well as Go's internal
	// randomness source. Native operations cannot use that testing source.
	return rand.IsDefaultReader(r) && rand.IsDefaultReader(cryptorand.Reader)
}

func curveName[P Point[P]](c *Curve[P]) string {
	switch any(c) {
	case any(fallback.P224()):
		return "P-224"
	case any(fallback.P256()):
		return "P-256"
	case any(fallback.P384()):
		return "P-384"
	case any(fallback.P521()):
		return "P-521"
	}
	return ""
}

func wrapPrivateKey(name string, key *fipsPrivateKey) *PrivateKey {
	k := &PrivateKey{pub: PublicKey{curve: name, q: key.PublicKey().Bytes()}, d: key.Bytes()}
	k.pub.fips.key.Store(key.PublicKey())
	k.fips.key.Store(key)
	return k
}

// NewPublicKey validates a public point with the Go implementation.
// Native key conversion is deferred until a native operation needs it.
// Q is retained by the returned key and must not be modified.
func NewPublicKey[P Point[P]](c *Curve[P], Q []byte) (*PublicKey, error) {
	key, err := fallback.NewPublicKey(c, Q)
	if err != nil {
		return nil, err
	}
	k := &PublicKey{curve: curveName(c), q: key.Bytes()}
	k.fips.key.Store(key)
	return k, nil
}

// NewPrivateKey validates private scalar and public point encodings with the
// Go implementation, retaining that key for deterministic signing and fallback.
// D is copied. Q is retained by the returned key and must not be modified.
func NewPrivateKey[P Point[P]](c *Curve[P], D, Q []byte) (*PrivateKey, error) {
	key, err := fallback.NewPrivateKey(c, D, Q)
	if err != nil {
		return nil, err
	}
	return wrapPrivateKey(curveName(c), key), nil
}

// GenerateKey selects native generation when the curve and random source are
// supported, and otherwise uses the Go implementation.
func GenerateKey[P Point[P]](c *Curve[P], random io.Reader) (*PrivateKey, error) {
	name := curveName(c)
	if backend.Enabled && isDefaultReader(random) && supportsCurve(name) {
		x, y, d, err := generateKey(name)
		if err != nil {
			return nil, err
		}
		size := c.N.Size()
		X, Y, D := bbig.Dec(x), bbig.Dec(y), bbig.Dec(d)
		if X == nil || Y == nil || D == nil || X.BitLen() > size*8 || Y.BitLen() > size*8 || D.BitLen() > size*8 {
			return nil, errors.New("ecdsa: invalid generated key parameters")
		}
		Q := make([]byte, 1+2*size)
		Q[0] = 4
		X.FillBytes(Q[1 : 1+size])
		Y.FillBytes(Q[1+size:])
		return &PrivateKey{pub: PublicKey{curve: name, q: Q}, d: D.FillBytes(make([]byte, size))}, nil
	}
	key, err := fallback.GenerateKey(c, random)
	if err != nil {
		return nil, err
	}
	return wrapPrivateKey(name, key), nil
}

func privateGoKey[P Point[P]](c *Curve[P], k *PrivateKey) (*fipsPrivateKey, error) {
	return k.fips.get(func() (*fipsPrivateKey, error) {
		return fallback.NewPrivateKey(c, k.d, k.pub.q)
	})
}

func Sign[P Point[P], H hash.Hash](c *Curve[P], h func() H, priv *PrivateKey, random io.Reader, digest []byte) (*Signature, error) {
	if priv.pub.curve != curveName(c) {
		return nil, errors.New("ecdsa: private key does not match curve")
	}
	if len(digest) == 0 {
		return nil, errors.New("ecdsa: hash cannot be empty")
	}
	if priv.pub.supportsBackend() && isDefaultReader(random) {
		key, err := priv.backendKey()
		if err != nil {
			return nil, err
		}
		return sign(key, digest)
	}
	key, err := privateGoKey(c, priv)
	if err != nil {
		return nil, err
	}
	return fallback.Sign(c, h, key, random, digest)
}

// SignDeterministic always uses the Go implementation for RFC 6979 signing.
func SignDeterministic[P Point[P], H hash.Hash](c *Curve[P], h func() H, priv *PrivateKey, digest []byte) (*Signature, error) {
	if priv.pub.curve != curveName(c) {
		return nil, errors.New("ecdsa: private key does not match curve")
	}
	key, err := privateGoKey(c, priv)
	if err != nil {
		return nil, err
	}
	return fallback.SignDeterministic(c, h, key, digest)
}

func Verify[P Point[P]](c *Curve[P], pub *PublicKey, digest []byte, sig *Signature) error {
	if pub.curve != curveName(c) {
		return errors.New("ecdsa: public key does not match curve")
	}
	if len(digest) == 0 {
		return errors.New("ecdsa: hash cannot be empty")
	}
	if pub.supportsBackend() {
		key, err := pub.backendKey()
		if err != nil {
			return err
		}
		return verify(key, digest, sig)
	}
	key, err := pub.fips.get(func() (*fipsPublicKey, error) {
		return fallback.NewPublicKey(c, pub.q)
	})
	if err != nil {
		return err
	}
	return fallback.Verify(c, key, digest, sig)
}
