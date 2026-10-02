// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh

import (
	"errors"

	backend "github.com/microsoft/go/cryptobackend"
)

// PublicKey holds an immutable ECDH public key and its implementation.
type PublicKey struct {
	curve   string
	q       []byte
	backend *backendPublicKey
	fips    *fipsPublicKey
}

// Bytes returns the public key encoding. The returned slice must not be modified.
func (k *PublicKey) Bytes() []byte { return k.q }

// PrivateKey holds an immutable ECDH private key and its implementation.
type PrivateKey struct {
	pub     PublicKey
	d       []byte
	backend *backendPrivateKey
	fips    *fipsPrivateKey
}

// Bytes returns the private key encoding. The returned slice must not be modified.
func (k *PrivateKey) Bytes() []byte { return k.d }

// PublicKey returns the public part of k.
func (k *PrivateKey) PublicKey() *PublicKey { return &k.pub }

func supportsBackend(curve string) bool {
	return backend.Enabled && SupportsCurve(curve)
}

// importBackendPrivateKey takes ownership of key and normalizes import errors.
func importBackendPrivateKey(curve string, key []byte) (*PrivateKey, error) {
	native, err := newPrivateKey(curve, key)
	if err != nil {
		return nil, errors.New("crypto/ecdh: invalid private key")
	}
	k, err := wrapBackendPrivateKey(curve, native, key)
	if err != nil {
		return nil, errors.New("crypto/ecdh: invalid private key")
	}
	return k, nil
}

// wrapBackendPrivateKey takes ownership of the private key encoding.
func wrapBackendPrivateKey(curve string, key *backendPrivateKey, d []byte) (*PrivateKey, error) {
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		pub:     PublicKey{curve: curve, q: pub.Bytes(), backend: pub},
		d:       d,
		backend: key,
	}, nil
}
