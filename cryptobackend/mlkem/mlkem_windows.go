// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mlkem

import "github.com/microsoft/go-crypto-winnative/cng"

type backendDecapsulationKey768 = cng.DecapsulationKeyMLKEM768
type backendEncapsulationKey768 = cng.EncapsulationKeyMLKEM768
type backendDecapsulationKey1024 = cng.DecapsulationKeyMLKEM1024
type backendEncapsulationKey1024 = cng.EncapsulationKeyMLKEM1024

func Supports768() bool                                   { return cng.SupportsMLKEM() }
func Supports1024() bool                                  { return cng.SupportsMLKEM() }
func generateKey768() (backendDecapsulationKey768, error) { return cng.GenerateKeyMLKEM768() }
func newDecapsulationKey768(seed []byte) (backendDecapsulationKey768, error) {
	return cng.NewDecapsulationKeyMLKEM768(seed)
}
func newEncapsulationKey768(encapsulationKey []byte) (backendEncapsulationKey768, error) {
	return cng.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func generateKey1024() (backendDecapsulationKey1024, error) { return cng.GenerateKeyMLKEM1024() }
func newDecapsulationKey1024(seed []byte) (backendDecapsulationKey1024, error) {
	return cng.NewDecapsulationKeyMLKEM1024(seed)
}
func newEncapsulationKey1024(encapsulationKey []byte) (backendEncapsulationKey1024, error) {
	return cng.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
