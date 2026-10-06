// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"sync"

	backend "github.com/microsoft/go/cryptobackend"
)

// PrivateKey holds an ML-DSA private key. It is safe for concurrent use and
// can be copied: lazy Go-key reconstruction is shared through backend.
type PrivateKey struct {
	fips    *fipsPrivateKey
	backend *backendPrivateKeyState
}

// Native keys hold only parameter metadata and a seed, so the key can live
// in the shared reconstruction state without a separate allocation on import.
type backendPrivateKeyState struct {
	key       backendPrivateKey
	goKeyOnce sync.Once
	goKey     *fipsPrivateKey
	goKeyErr  error
}

// PublicKey holds an ML-DSA public key. Its Go representation is stored by
// value so a derived public key does not retain the Go private key.
type PublicKey struct {
	fips    fipsPublicKey
	backend *backendPublicKey
}

func nativeParameters(name string) (Parameters, bool) {
	if !backend.Enabled {
		return Parameters{}, false
	}
	var params Parameters
	switch name {
	case "ML-DSA-44":
		params = MLDSA44()
	case "ML-DSA-65":
		params = MLDSA65()
	case "ML-DSA-87":
		params = MLDSA87()
	default:
		return Parameters{}, false
	}
	return params, Supports(params)
}

// Bytes returns a copy of the private key seed.
func (k *PrivateKey) Bytes() []byte {
	if k.backend != nil {
		var seed [32]byte
		copy(seed[:], k.backend.key.Bytes())
		return seed[:]
	}
	if k.fips == nil {
		return make([]byte, 32)
	}
	return k.fips.Bytes()
}

// PublicKey returns the corresponding public key.
func (k *PrivateKey) PublicKey() *PublicKey {
	pub := k.publicKey()
	return &pub
}

func (k *PrivateKey) publicKey() PublicKey {
	if k.backend != nil {
		return PublicKey{backend: k.backend.key.PublicKey()}
	}
	if k.fips == nil {
		return PublicKey{}
	}
	return PublicKey{fips: *k.fips.PublicKey()}
}

// Equal reports whether k and other have the same parameter set and seed.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	if k.backend != nil && other.backend != nil {
		return k.backend.key.Equal(&other.backend.key)
	}
	if k.backend != nil {
		if other.fips == nil || k.backend.key.Parameters().String() != other.fips.PublicKey().Parameters() {
			return false
		}
		return subtle.ConstantTimeCompare(k.backend.key.Bytes(), other.fips.Bytes()) == 1
	}
	if other.backend != nil {
		return other.Equal(k)
	}
	if k.fips == nil || other.fips == nil {
		return k.fips == other.fips
	}
	return k.fips.Equal(other.fips)
}

// goKey retains a reconstructed Go key for deterministic and unsupported
// operations. Only the shared state is mutated, keeping PrivateKey comparable.
func (k *PrivateKey) goKey() (*fipsPrivateKey, error) {
	if k.fips != nil {
		return k.fips, nil
	}
	if k.backend == nil {
		return nil, errors.New("mldsa: zero private key")
	}
	s := k.backend
	s.goKeyOnce.Do(func() {
		s.goKey, s.goKeyErr = newGoPrivateKey(s.key.Parameters().String(), s.key.Bytes())
	})
	return s.goKey, s.goKeyErr
}

// Bytes returns a copy of the public key encoding.
func (k *PublicKey) Bytes() []byte {
	if k.backend != nil {
		return bytes.Clone(k.backend.Bytes())
	}
	return k.fips.Bytes()
}

// Parameters returns the parameter set's name.
func (k *PublicKey) Parameters() string {
	if k.backend != nil {
		return k.backend.Parameters().String()
	}
	return k.fips.Parameters()
}

// Equal reports whether k and other have the same parameter set and encoding.
func (k *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	if k.backend != nil && other.backend != nil {
		return k.backend.Equal(other.backend)
	}
	if k.backend != nil {
		if other.fips == (fipsPublicKey{}) || k.Parameters() != other.Parameters() {
			return false
		}
		return subtle.ConstantTimeCompare(k.backend.Bytes(), other.fips.Bytes()) == 1
	}
	if other.backend != nil {
		return other.Equal(k)
	}
	return k.fips.Equal(&other.fips)
}
