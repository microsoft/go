// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"sync"
	"sync/atomic"

	backend "github.com/microsoft/go/cryptobackend"
)

// lazyKey retains successful conversions, but permits retrying failed imports.
type lazyKey[T any] struct {
	key atomic.Pointer[T]
	mu  sync.Mutex
}

func (k *lazyKey[T]) get(new func() (*T, error)) (*T, error) {
	if key := k.key.Load(); key != nil {
		return key, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if key := k.key.Load(); key != nil {
		return key, nil
	}
	key, err := new()
	if err != nil {
		return nil, err
	}
	k.key.Store(key)
	return key, nil
}

// PublicKey holds an ECDSA public key and its cached implementations.
// A PublicKey must not be copied after first use.
type PublicKey struct {
	curve   string
	q       []byte
	backend lazyKey[backendPublicKey]
	fips    lazyKey[fipsPublicKey]
}

// Bytes returns the public point encoding.
// The returned slice must not be modified.
func (k *PublicKey) Bytes() []byte {
	return k.q
}

func (k *PublicKey) supportsBackend() bool {
	// Native imports take affine coordinates. Keep other encodings accepted by
	// the Go constructor, including compressed points, on the Go path.
	return backend.Enabled && len(k.q) > 0 && k.q[0] == 4 && supportsCurve(k.curve)
}

func (k *PublicKey) backendKey() (*backendPublicKey, error) {
	return k.backend.get(func() (*backendPublicKey, error) {
		return newPublicKey(k.curve, k.q)
	})
}

// PrivateKey holds an ECDSA private key and its cached implementations.
// A PrivateKey must not be copied after first use.
type PrivateKey struct {
	pub     PublicKey
	d       []byte
	backend lazyKey[backendPrivateKey]
	fips    lazyKey[fipsPrivateKey]
}

// Bytes returns the private scalar encoding.
// The returned slice must not be modified.
func (k *PrivateKey) Bytes() []byte {
	return k.d
}

// PublicKey returns the public part of k.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &k.pub
}

func (k *PrivateKey) backendKey() (*backendPrivateKey, error) {
	return k.backend.get(func() (*backendPrivateKey, error) {
		return newPrivateKey(k.pub.curve, k.pub.q, k.d)
	})
}
