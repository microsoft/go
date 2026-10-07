// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto && (msgostd || cmd_go_bootstrap)

package mlkem

import (
	fallback "crypto/internal/fips140/mlkem"
	"crypto/internal/rand"
	cryptorand "crypto/rand"
	"errors"
)

type fipsDecapsulationKey768 = fallback.DecapsulationKey768
type fipsEncapsulationKey768 = fallback.EncapsulationKey768
type fipsDecapsulationKey1024 = fallback.DecapsulationKey1024
type fipsEncapsulationKey1024 = fallback.EncapsulationKey1024

func defaultRandomReader() bool { return rand.IsDefaultReader(cryptorand.Reader) }

func GenerateKey768() (key *DecapsulationKey768, err error) {
	var k DecapsulationKey768
	err = generate768(&k)
	if err == nil {
		key = &k
	}
	return
}

func generate768(k *DecapsulationKey768) error {
	if supportsBackend768() && defaultRandomReader() {
		key, err := generateKey768()
		if err != nil {
			return err
		}
		k.backend, k.native = key, true
		return nil
	}
	key, err := fallback.GenerateKey768()
	k.fips = key
	return err
}

func GenerateKey1024() (key *DecapsulationKey1024, err error) {
	var k DecapsulationKey1024
	err = generate1024(&k)
	if err == nil {
		key = &k
	}
	return
}

func generate1024(k *DecapsulationKey1024) error {
	if supportsBackend1024() && defaultRandomReader() {
		key, err := generateKey1024()
		if err != nil {
			return err
		}
		k.backend, k.native = key, true
		return nil
	}
	key, err := fallback.GenerateKey1024()
	k.fips = key
	return err
}

func NewDecapsulationKey768(seed []byte) (key *DecapsulationKey768, err error) {
	var k DecapsulationKey768
	err = newDecapsulation768(&k, seed)
	if err == nil {
		key = &k
	}
	return
}

func newDecapsulation768(k *DecapsulationKey768, seed []byte) error {
	if len(seed) != 64 {
		return errors.New("mlkem: invalid seed length")
	}
	if supportsBackend768() {
		key, err := newDecapsulationKey768(seed)
		if err != nil {
			return err
		}
		k.backend, k.native = key, true
		return nil
	}
	key, err := fallback.NewDecapsulationKey768(seed)
	k.fips = key
	return err
}

func NewDecapsulationKey1024(seed []byte) (key *DecapsulationKey1024, err error) {
	var k DecapsulationKey1024
	err = newDecapsulation1024(&k, seed)
	if err == nil {
		key = &k
	}
	return
}

func newDecapsulation1024(k *DecapsulationKey1024, seed []byte) error {
	if len(seed) != 64 {
		return errors.New("mlkem: invalid seed length")
	}
	if supportsBackend1024() {
		key, err := newDecapsulationKey1024(seed)
		if err != nil {
			return err
		}
		k.backend, k.native = key, true
		return nil
	}
	key, err := fallback.NewDecapsulationKey1024(seed)
	k.fips = key
	return err
}

func NewEncapsulationKey768(encoding []byte) (*EncapsulationKey768, error) {
	if supportsBackend768() {
		if err := checkEncapsulationKey(encoding, 1184); err != nil {
			return nil, err
		}
		key, err := newEncapsulationKey768(encoding)
		if err != nil {
			return nil, err
		}
		return newBackendEncapsulationKey768(key), nil
	}
	key, err := fallback.NewEncapsulationKey768(encoding)
	if err != nil {
		return nil, err
	}
	return &EncapsulationKey768{fips: key}, nil
}

func NewEncapsulationKey1024(encoding []byte) (*EncapsulationKey1024, error) {
	if supportsBackend1024() {
		if err := checkEncapsulationKey(encoding, 1568); err != nil {
			return nil, err
		}
		key, err := newEncapsulationKey1024(encoding)
		if err != nil {
			return nil, err
		}
		return newBackendEncapsulationKey1024(key), nil
	}
	key, err := fallback.NewEncapsulationKey1024(encoding)
	if err != nil {
		return nil, err
	}
	return &EncapsulationKey1024{fips: key}, nil
}

func newGoEncapsulationKey768(encoding []byte) (*fipsEncapsulationKey768, error) {
	return fallback.NewEncapsulationKey768(encoding)
}

func newGoEncapsulationKey1024(encoding []byte) (*fipsEncapsulationKey1024, error) {
	return fallback.NewEncapsulationKey1024(encoding)
}
