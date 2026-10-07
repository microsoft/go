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
	native  bool
}

type DecapsulationKey1024 struct {
	fips    *fipsDecapsulationKey1024
	backend backendDecapsulationKey1024
	native  bool
}

// Encapsulation keys share the lazy Go representation when copied. The Go key
// is only needed if the global random reader is overridden after native import.
type EncapsulationKey768 struct {
	fips    *fipsEncapsulationKey768
	backend *backendEncapsulationKey768State
}

type EncapsulationKey1024 struct {
	fips    *fipsEncapsulationKey1024
	backend *backendEncapsulationKey1024State
}

// Co-locate the returned wrapper, immutable native key and shared fallback
// state so a native public-key import needs only one allocation in this layer.
type backendEncapsulationKey768State struct {
	wrapper   EncapsulationKey768
	key       backendEncapsulationKey768
	goKeyOnce sync.Once
	goKey     *fipsEncapsulationKey768
	goKeyErr  error
}

type backendEncapsulationKey1024State struct {
	wrapper   EncapsulationKey1024
	key       backendEncapsulationKey1024
	goKeyOnce sync.Once
	goKey     *fipsEncapsulationKey1024
	goKeyErr  error
}

func newBackendEncapsulationKey768(key backendEncapsulationKey768) *EncapsulationKey768 {
	s := &backendEncapsulationKey768State{key: key}
	s.wrapper.backend = s
	return &s.wrapper
}

func newBackendEncapsulationKey1024(key backendEncapsulationKey1024) *EncapsulationKey1024 {
	s := &backendEncapsulationKey1024State{key: key}
	s.wrapper.backend = s
	return &s.wrapper
}

// Bytes returns a copy of the decapsulation key seed.
func (dk *DecapsulationKey768) Bytes() []byte {
	if dk.native {
		return dk.backend.Bytes()
	}
	return dk.fips.Bytes()
}

func (dk *DecapsulationKey1024) Bytes() []byte {
	if dk.native {
		return dk.backend.Bytes()
	}
	return dk.fips.Bytes()
}

func (dk *DecapsulationKey768) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 1088 {
		return nil, errors.New("mlkem: invalid ciphertext length")
	}
	if dk.native {
		return dk.backend.Decapsulate(ciphertext)
	}
	return dk.fips.Decapsulate(ciphertext)
}

func (dk *DecapsulationKey1024) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 1568 {
		return nil, errors.New("mlkem: invalid ciphertext length")
	}
	if dk.native {
		return dk.backend.Decapsulate(ciphertext)
	}
	return dk.fips.Decapsulate(ciphertext)
}

func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768 {
	if dk.native {
		return newBackendEncapsulationKey768(dk.backend.EncapsulationKey())
	}
	return &EncapsulationKey768{fips: dk.fips.EncapsulationKey()}
}

func (dk *DecapsulationKey1024) EncapsulationKey() *EncapsulationKey1024 {
	if dk.native {
		return newBackendEncapsulationKey1024(dk.backend.EncapsulationKey())
	}
	return &EncapsulationKey1024{fips: dk.fips.EncapsulationKey()}
}

// The providers' Bytes methods have value receivers on fixed-size arrays, so
// they return independent encodings rather than exposing the stored native key.
func (ek *EncapsulationKey768) Bytes() []byte {
	if ek.backend != nil {
		return ek.backend.key.Bytes()
	}
	return ek.fips.Bytes()
}

func (ek *EncapsulationKey1024) Bytes() []byte {
	if ek.backend != nil {
		return ek.backend.key.Bytes()
	}
	return ek.fips.Bytes()
}

func (ek *EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte) {
	if ek.backend != nil && defaultRandomReader() {
		return ek.backend.key.Encapsulate()
	}
	return ek.goKey().Encapsulate()
}

func (ek *EncapsulationKey1024) Encapsulate() (sharedKey, ciphertext []byte) {
	if ek.backend != nil && defaultRandomReader() {
		return ek.backend.key.Encapsulate()
	}
	return ek.goKey().Encapsulate()
}

func (ek *EncapsulationKey768) goKey() *fipsEncapsulationKey768 {
	if ek.backend == nil {
		return ek.fips
	}
	s := ek.backend
	s.goKeyOnce.Do(func() {
		s.goKey, s.goKeyErr = newGoEncapsulationKey768(s.key.Bytes())
	})
	if s.goKeyErr != nil {
		panic(s.goKeyErr)
	}
	return s.goKey
}

func (ek *EncapsulationKey1024) goKey() *fipsEncapsulationKey1024 {
	if ek.backend == nil {
		return ek.fips
	}
	s := ek.backend
	s.goKeyOnce.Do(func() {
		s.goKey, s.goKeyErr = newGoEncapsulationKey1024(s.key.Bytes())
	})
	if s.goKeyErr != nil {
		panic(s.goKeyErr)
	}
	return s.goKey
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
