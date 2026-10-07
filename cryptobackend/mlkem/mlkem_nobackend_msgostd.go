// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto && (msgostd || cmd_go_bootstrap)

package mlkem

import (
	fallback "crypto/internal/fips140/mlkem"

	_ "github.com/microsoft/go/cryptobackend"
)

// Go-only builds use the core key types directly, without wrapper allocations.
type DecapsulationKey768 = fallback.DecapsulationKey768
type EncapsulationKey768 = fallback.EncapsulationKey768
type DecapsulationKey1024 = fallback.DecapsulationKey1024
type EncapsulationKey1024 = fallback.EncapsulationKey1024

func GenerateKey768() (*DecapsulationKey768, error)   { return fallback.GenerateKey768() }
func GenerateKey1024() (*DecapsulationKey1024, error) { return fallback.GenerateKey1024() }
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error) {
	return fallback.NewDecapsulationKey768(seed)
}
func NewDecapsulationKey1024(seed []byte) (*DecapsulationKey1024, error) {
	return fallback.NewDecapsulationKey1024(seed)
}
func NewEncapsulationKey768(encoding []byte) (*EncapsulationKey768, error) {
	return fallback.NewEncapsulationKey768(encoding)
}
func NewEncapsulationKey1024(encoding []byte) (*EncapsulationKey1024, error) {
	return fallback.NewEncapsulationKey1024(encoding)
}
