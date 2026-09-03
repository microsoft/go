// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import "github.com/microsoft/go/cryptobackend"

type shakeAlgorithm uint8

const (
	shake256 shakeAlgorithm = iota
	shake128
	cshake128
	cshake256
)

// SHAKE dispatches SHAKE and cSHAKE operations to a native or fallback implementation.
// Its zero value is a usable SHAKE256 instance.
type SHAKE struct {
	fallback    fallbackSHAKE
	backend     *backendSHAKE
	algorithm   shakeAlgorithm
	initialized bool
}

func newSHAKE(algorithm shakeAlgorithm) *SHAKE {
	return &SHAKE{algorithm: algorithm}
}

func (s *SHAKE) init() {
	if s.initialized {
		return
	}
	s.initialized = true
	switch s.algorithm {
	case shake256:
		if backend.Enabled && SupportsSHAKE(256) {
			s.backend = newBackendShake256()
			return
		}
		s.fallback = *newFallbackShake256()
	case shake128:
		if backend.Enabled && SupportsSHAKE(128) {
			s.backend = newBackendShake128()
			return
		}
		s.fallback = *newFallbackShake128()
	default:
		panic("cryptobackend: invalid SHAKE algorithm")
	}
}

// NewShake128 creates a new SHAKE128 XOF.
func NewShake128() *SHAKE { return newSHAKE(shake128) }

// NewShake256 creates a new SHAKE256 XOF.
func NewShake256() *SHAKE { return newSHAKE(shake256) }

// NewCShake128 creates a new cSHAKE128 XOF.
func NewCShake128(N, S []byte) *SHAKE {
	s := &SHAKE{algorithm: cshake128, initialized: true}
	if backend.Enabled && SupportsCSHAKE(128) {
		s.backend = newBackendCShake128(N, S)
	} else {
		s.fallback = *newFallbackCShake128(N, S)
	}
	return s
}

// NewCShake256 creates a new cSHAKE256 XOF.
func NewCShake256(N, S []byte) *SHAKE {
	s := &SHAKE{algorithm: cshake256, initialized: true}
	if backend.Enabled && SupportsCSHAKE(256) {
		s.backend = newBackendCShake256(N, S)
	} else {
		s.fallback = *newFallbackCShake256(N, S)
	}
	return s
}

// SumSHAKE128 applies SHAKE128 to data and returns length bytes of output.
func SumSHAKE128(data []byte, length int) []byte {
	if backend.Enabled && SupportsSHAKE(128) {
		return sumSHAKE128(data, length)
	}
	out := make([]byte, 32)
	return sumFallbackSHAKE(out, data, length, newFallbackShake128())
}

// SumSHAKE256 applies SHAKE256 to data and returns length bytes of output.
func SumSHAKE256(data []byte, length int) []byte {
	if backend.Enabled && SupportsSHAKE(256) {
		return sumSHAKE256(data, length)
	}
	out := make([]byte, 64)
	return sumFallbackSHAKE(out, data, length, newFallbackShake256())
}

func sumFallbackSHAKE(out, data []byte, length int, s *fallbackSHAKE) []byte {
	if len(out) < length {
		out = make([]byte, length)
	} else {
		out = out[:length]
	}
	s.Write(data)
	s.Read(out)
	return out
}

func (s *SHAKE) Write(p []byte) (int, error) {
	s.init()
	if s.backend != nil {
		return s.backend.Write(p)
	}
	return s.fallback.Write(p)
}

func (s *SHAKE) Read(p []byte) (int, error) {
	s.init()
	if s.backend != nil {
		return s.backend.Read(p)
	}
	return s.fallback.Read(p)
}

func (s *SHAKE) Reset() {
	s.init()
	if s.backend != nil {
		s.backend.Reset()
		return
	}
	s.fallback.Reset()
}

func (s *SHAKE) BlockSize() int {
	s.init()
	if s.backend != nil {
		return s.backend.BlockSize()
	}
	return s.fallback.BlockSize()
}

func (s *SHAKE) Size() int {
	switch s.algorithm {
	case shake128, cshake128:
		return 32
	case shake256, cshake256:
		return 64
	default:
		panic("cryptobackend: invalid SHAKE algorithm")
	}
}

func (s *SHAKE) MarshalBinary() ([]byte, error) {
	s.init()
	if s.backend != nil {
		return s.backend.MarshalBinary()
	}
	return s.fallback.MarshalBinary()
}

func (s *SHAKE) AppendBinary(p []byte) ([]byte, error) {
	s.init()
	if s.backend != nil {
		return s.backend.AppendBinary(p)
	}
	return s.fallback.AppendBinary(p)
}

func (s *SHAKE) UnmarshalBinary(data []byte) error {
	s.init()
	if s.backend != nil {
		return s.backend.UnmarshalBinary(data)
	}
	return s.fallback.UnmarshalBinary(data)
}
