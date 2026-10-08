// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (goexperiment.systemcrypto && !windows) || (!msgostd && !cmd_go_bootstrap)

package ed25519

import (
	"sync"

	backend "github.com/microsoft/go/cryptobackend"
)

// PrivateKey owns an immutable key snapshot. It must not be copied after use.
// The standard-library private-key cache retains pointers to these keys.
type PrivateKey struct {
	fips      *fipsPrivateKey
	backend   backendPrivateKey
	encoding  [64]byte
	goKeyOnce sync.Once
}

// PublicKey owns a public-key snapshot and lazily reconstructs its Go key.
// Copies share the native key's reconstruction state.
type PublicKey struct {
	fips    fipsPublicKey
	backend *backendPublicKeyState
}

type backendPublicKeyState struct {
	key       backendPublicKey
	encoding  [32]byte
	goKeyOnce sync.Once
	goKey     *fipsPublicKey
}

// Bytes returns a copy of the private key encoding, including its public suffix.
func (k *PrivateKey) Bytes() []byte {
	encoding := k.encoding
	return encoding[:]
}

// PrivateKeyBytes returns the owned snapshot for read-only cache comparisons.
func PrivateKeyBytes(k *PrivateKey) []byte { return k.encoding[:] }

// Seed returns a copy of the private key seed.
func (k *PrivateKey) Seed() []byte {
	seed := [32]byte(k.encoding[:32])
	return seed[:]
}

// PublicKey returns a copy of the public key encoding.
func (k *PrivateKey) PublicKey() []byte {
	pub := [32]byte(k.encoding[32:])
	return pub[:]
}

// Bytes returns a copy of the public key encoding.
func (k *PublicKey) Bytes() []byte {
	if k.backend != nil {
		encoding := k.backend.encoding
		return encoding[:]
	}
	return k.fips.Bytes()
}

// goKey caches the Go key needed for prehash and context signing.
func (k *PrivateKey) goKey() *fipsPrivateKey {
	if k.backend == nil {
		return k.fips
	}
	k.goKeyOnce.Do(func() {
		k.fips = newGoPrivateKey(&k.encoding)
	})
	return k.fips
}

func (k *PublicKey) goKey() *fipsPublicKey {
	if k.backend == nil {
		return &k.fips
	}
	s := k.backend
	s.goKeyOnce.Do(func() {
		s.goKey = newGoPublicKey(&s.encoding)
	})
	return s.goKey
}

func supportsBackend() bool { return backend.Enabled && Supports() }

// Old OpenSSL versions accept non-canonical signature scalars. Keep native
// verification disabled if the provider does not reject this malleable vector.
var testMalleability = sync.OnceValue(func() bool {
	msg := []byte{0x54, 0x65, 0x73, 0x74}
	sig := []byte{
		0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a,
		0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b,
		0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67,
		0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33,
		0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
	}
	pub, err := newPublicKey([]byte{
		0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5,
		0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34,
		0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
	})
	return err == nil && verify(pub, msg, sig) != nil
})
