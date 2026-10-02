// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package ecdh

import (
	"bytes"
	fallback "crypto/internal/fips140/ecdh"
	"crypto/internal/fips140/nistec"
	"crypto/internal/rand"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/bits"
)

type Point[P any] = fallback.Point[P]
type Curve[P Point[P]] = fallback.Curve[P]
type fipsPublicKey = fallback.PublicKey
type fipsPrivateKey = fallback.PrivateKey

func P224() *Curve[*nistec.P224Point] { return fallback.P224() }
func P256() *Curve[*nistec.P256Point] { return fallback.P256() }
func P384() *Curve[*nistec.P384Point] { return fallback.P384() }
func P521() *Curve[*nistec.P521Point] { return fallback.P521() }

func curveName[P Point[P]](c *Curve[P]) string {
	// Each supported NIST curve has a distinct scalar encoding length.
	switch len(c.N) {
	case 28:
		return "P-224"
	case 32:
		return "P-256"
	case 48:
		return "P-384"
	case 66:
		return "P-521"
	}
	return ""
}

func isDefaultReader(r io.Reader) bool {
	// SetGlobalRandom replaces the public reader as well as Go's internal
	// randomness source. Native generation cannot use that testing source.
	return rand.IsDefaultReader(r) && rand.IsDefaultReader(cryptorand.Reader)
}

func wrapGoPrivateKey(curve string, key *fipsPrivateKey) *PrivateKey {
	return &PrivateKey{
		pub:  PublicKey{curve: curve, q: key.PublicKey().Bytes(), fips: key.PublicKey()},
		d:    key.Bytes(),
		fips: key,
	}
}

func GenerateKey[P Point[P]](c *Curve[P], random io.Reader) (*PrivateKey, error) {
	name := curveName(c)
	if supportsBackend(name) && isDefaultReader(random) {
		key, d, err := generateKey(name)
		if err != nil {
			return nil, err
		}
		return wrapBackendPrivateKey(name, key, d)
	}
	key, err := fallback.GenerateKey(c, random)
	if err != nil {
		return nil, err
	}
	if supportsBackend(name) {
		// Custom randomness selects Go generation, not a different ECDH
		// implementation. Keep generated and imported keys interoperable.
		native, err := newPrivateKey(name, key.Bytes())
		if err != nil {
			return nil, err
		}
		return wrapBackendPrivateKey(name, native, key.Bytes())
	}
	return wrapGoPrivateKey(name, key), nil
}

func NewPrivateKey[P Point[P]](c *Curve[P], key []byte) (*PrivateKey, error) {
	name := curveName(c)
	if supportsBackend(name) {
		// Some native imports reduce scalars modulo the curve order. Enforce
		// Go's fixed-length, nonzero, reduced encoding before importing.
		if !validScalar(key, c.N) {
			return nil, errors.New("crypto/ecdh: invalid private key")
		}
		return importBackendPrivateKey(name, bytes.Clone(key))
	}
	k, err := fallback.NewPrivateKey(c, key)
	if err != nil {
		return nil, err
	}
	return wrapGoPrivateKey(name, k), nil
}

func NewPublicKey[P Point[P]](c *Curve[P], key []byte) (*PublicKey, error) {
	name := curveName(c)
	if supportsBackend(name) {
		if len(key) == 0 || key[0] != 4 {
			return nil, errors.New("crypto/ecdh: invalid public key")
		}
		native, err := newPublicKey(name, key)
		if err != nil {
			return nil, errors.New("crypto/ecdh: invalid public key")
		}
		return &PublicKey{curve: name, q: native.Bytes(), backend: native}, nil
	}
	k, err := fallback.NewPublicKey(c, key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{curve: name, q: k.Bytes(), fips: k}, nil
}

func ECDH[P Point[P]](c *Curve[P], priv *PrivateKey, pub *PublicKey) ([]byte, error) {
	if name := curveName(c); priv.pub.curve != name || pub.curve != name {
		return nil, errors.New("crypto/ecdh: mismatched curves")
	}
	if priv.backend != nil {
		return ecdh(priv.backend, pub.backend)
	}
	return fallback.ECDH(c, priv.fips, pub.fips)
}

func validScalar(key, order []byte) bool {
	if len(key) != len(order) {
		return false
	}
	var nonzero byte
	var borrow uint64
	for i := len(key) - 1; i >= 0; i-- {
		nonzero |= key[i]
		_, borrow = bits.Sub64(uint64(key[i]), uint64(order[i]), borrow)
	}
	return nonzero != 0 && borrow == 1
}
