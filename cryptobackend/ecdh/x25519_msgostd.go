// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build msgostd || cmd_go_bootstrap

package ecdh

import (
	"bytes"
	"crypto/internal/fips140/drbg"
	"errors"
	"io"
)

// The scalar multiplication callbacks keep the upstream X25519 implementation
// in crypto/ecdh while letting this package select native operations or fallback.

func GenerateKeyX25519(random io.Reader, scalarBaseMult func(dst, scalar []byte)) (*PrivateKey, error) {
	if supportsBackend("X25519") && isDefaultReader(random) {
		key, d, err := generateKey("X25519")
		if err != nil {
			return nil, err
		}
		return wrapBackendPrivateKey("X25519", key, d)
	}
	key := make([]byte, 32)
	if err := drbg.ReadWithReader(random, key); err != nil {
		return nil, err
	}
	return newPrivateKeyX25519(key, scalarBaseMult)
}

func NewPrivateKeyX25519(key []byte, scalarBaseMult func(dst, scalar []byte)) (*PrivateKey, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto/ecdh: invalid private key size")
	}
	return newPrivateKeyX25519(bytes.Clone(key), scalarBaseMult)
}

// newPrivateKeyX25519 takes ownership of a 32-byte private scalar.
func newPrivateKeyX25519(key []byte, scalarBaseMult func(dst, scalar []byte)) (*PrivateKey, error) {
	if supportsBackend("X25519") {
		return importBackendPrivateKey("X25519", key)
	}
	publicKey := make([]byte, 32)
	scalarBaseMult(publicKey, key)
	return &PrivateKey{
		pub: PublicKey{curve: "X25519", q: publicKey},
		d:   key,
	}, nil
}

func NewPublicKeyX25519(key []byte) (*PublicKey, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto/ecdh: invalid public key")
	}
	if supportsBackend("X25519") {
		native, err := newPublicKey("X25519", key)
		if err == nil {
			return &PublicKey{curve: "X25519", q: native.Bytes(), backend: native}, nil
		}
		// X25519 accepts every 32-byte public encoding, including points on
		// the twist and non-canonical encodings. A backend may reject those
		// at import time; keep them for Go scalar multiplication instead.
	}
	return &PublicKey{curve: "X25519", q: bytes.Clone(key)}, nil
}

func ECDHX25519(priv *PrivateKey, pub *PublicKey, scalarMult func(dst, scalar, point []byte)) ([]byte, error) {
	if priv.pub.curve != "X25519" || pub.curve != "X25519" {
		return nil, errors.New("crypto/ecdh: mismatched curves")
	}
	var out []byte
	if priv.backend != nil && pub.backend != nil {
		var err error
		out, err = ecdh(priv.backend, pub.backend)
		if err != nil {
			return nil, err
		}
	} else {
		out = make([]byte, 32)
		scalarMult(out, priv.d, pub.q)
	}
	var nonzero byte
	for _, b := range out {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("crypto/ecdh: bad X25519 remote ECDH input: low order point")
	}
	return out, nil
}
