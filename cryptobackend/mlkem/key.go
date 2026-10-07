// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto || (!msgostd && !cmd_go_bootstrap)

package mlkem

import (
	"errors"
	"sync"

	"github.com/microsoft/go/cryptobackend"
)

// Native decapsulation keys hold only a seed, so they can be stored by value.
type DecapsulationKey768 struct {
	fips    *fipsDecapsulationKey768
	backend backendDecapsulationKey768
}

type DecapsulationKey1024 struct {
	fips    *fipsDecapsulationKey1024
	backend backendDecapsulationKey1024
}

// Encapsulation keys must not be copied after first use. Standard-library key
// wrappers share them through a pointer, including the lazy Go representation.
type EncapsulationKey768 struct {
	fips      *fipsEncapsulationKey768
	backend   *backendEncapsulationKey768
	goKeyOnce sync.Once
	goKeyErr  error
}

type EncapsulationKey1024 struct {
	fips      *fipsEncapsulationKey1024
	backend   *backendEncapsulationKey1024
	goKeyOnce sync.Once
	goKeyErr  error
}

// Allocate native key storage with the pointer-owned encapsulation key.
func newBackendEncapsulationKey768(key backendEncapsulationKey768) *EncapsulationKey768 {
	s := &struct {
		EncapsulationKey768
		key backendEncapsulationKey768
	}{key: key}
	s.backend = &s.key
	return &s.EncapsulationKey768
}

func newBackendEncapsulationKey1024(key backendEncapsulationKey1024) *EncapsulationKey1024 {
	s := &struct {
		EncapsulationKey1024
		key backendEncapsulationKey1024
	}{key: key}
	s.backend = &s.key
	return &s.EncapsulationKey1024
}

// Bytes returns a copy of the decapsulation key seed.
func (dk *DecapsulationKey768) Bytes() []byte {
	if dk.fips == nil {
		return dk.backend.Bytes()
	}
	return dk.fips.Bytes()
}

func (dk *DecapsulationKey1024) Bytes() []byte {
	if dk.fips == nil {
		return dk.backend.Bytes()
	}
	return dk.fips.Bytes()
}

func (dk *DecapsulationKey768) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 1088 {
		return nil, errors.New("mlkem: invalid ciphertext length")
	}
	if dk.fips == nil {
		return dk.backend.Decapsulate(ciphertext)
	}
	return dk.fips.Decapsulate(ciphertext)
}

func (dk *DecapsulationKey1024) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 1568 {
		return nil, errors.New("mlkem: invalid ciphertext length")
	}
	if dk.fips == nil {
		return dk.backend.Decapsulate(ciphertext)
	}
	return dk.fips.Decapsulate(ciphertext)
}

func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768 {
	if dk.fips == nil {
		return newBackendEncapsulationKey768(dk.backend.EncapsulationKey())
	}
	return &EncapsulationKey768{fips: dk.fips.EncapsulationKey()}
}

func (dk *DecapsulationKey1024) EncapsulationKey() *EncapsulationKey1024 {
	if dk.fips == nil {
		return newBackendEncapsulationKey1024(dk.backend.EncapsulationKey())
	}
	return &EncapsulationKey1024{fips: dk.fips.EncapsulationKey()}
}

// The providers' Bytes methods have value receivers on fixed-size arrays, so
// they return independent encodings rather than exposing the stored native key.
func (ek *EncapsulationKey768) Bytes() []byte {
	if ek.backend != nil {
		return ek.backend.Bytes()
	}
	return ek.fips.Bytes()
}

func (ek *EncapsulationKey1024) Bytes() []byte {
	if ek.backend != nil {
		return ek.backend.Bytes()
	}
	return ek.fips.Bytes()
}

func (ek *EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte) {
	if ek.backend != nil && defaultRandomReader() {
		return ek.backend.Encapsulate()
	}
	return ek.goKey().Encapsulate()
}

func (ek *EncapsulationKey1024) Encapsulate() (sharedKey, ciphertext []byte) {
	if ek.backend != nil && defaultRandomReader() {
		return ek.backend.Encapsulate()
	}
	return ek.goKey().Encapsulate()
}

func (ek *EncapsulationKey768) goKey() *fipsEncapsulationKey768 {
	if ek.backend == nil {
		return ek.fips
	}
	ek.goKeyOnce.Do(func() {
		ek.fips, ek.goKeyErr = newGoEncapsulationKey768(ek.backend.Bytes())
	})
	if ek.goKeyErr != nil {
		panic(ek.goKeyErr)
	}
	return ek.fips
}

func (ek *EncapsulationKey1024) goKey() *fipsEncapsulationKey1024 {
	if ek.backend == nil {
		return ek.fips
	}
	ek.goKeyOnce.Do(func() {
		ek.fips, ek.goKeyErr = newGoEncapsulationKey1024(ek.backend.Bytes())
	})
	if ek.goKeyErr != nil {
		panic(ek.goKeyErr)
	}
	return ek.fips
}

// The native importers only check length. Reject non-canonical 12-bit
// coefficients before accepting a key, as required by FIPS 203, Section 7.2.
func checkEncapsulationKey(encoding []byte, size int) error {
	if len(encoding) != size {
		return errors.New("mlkem: invalid encapsulation key length")
	}
	for i := 0; i < len(encoding)-32; i += 3 {
		x := uint16(encoding[i]) | uint16(encoding[i+1]&0x0f)<<8
		y := uint16(encoding[i+1]>>4) | uint16(encoding[i+2])<<4
		if x >= 3329 || y >= 3329 {
			return errors.New("mlkem: invalid polynomial encoding")
		}
	}
	return nil
}

func supportsBackend768() bool  { return backend.Enabled && Supports768() }
func supportsBackend1024() bool { return backend.Enabled && Supports1024() }
