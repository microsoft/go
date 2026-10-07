// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mlkem

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type backendDecapsulationKey768 = xcrypto.DecapsulationKeyMLKEM768
type backendEncapsulationKey768 = xcrypto.EncapsulationKeyMLKEM768
type backendDecapsulationKey1024 = xcrypto.DecapsulationKeyMLKEM1024
type backendEncapsulationKey1024 = xcrypto.EncapsulationKeyMLKEM1024

func Supports768() bool                                   { return xcrypto.SupportsMLKEM() }
func Supports1024() bool                                  { return xcrypto.SupportsMLKEM() }
func generateKey768() (backendDecapsulationKey768, error) { return xcrypto.GenerateKeyMLKEM768() }
func newDecapsulationKey768(seed []byte) (backendDecapsulationKey768, error) {
	return xcrypto.NewDecapsulationKeyMLKEM768(seed)
}
func newEncapsulationKey768(encapsulationKey []byte) (backendEncapsulationKey768, error) {
	return xcrypto.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func generateKey1024() (backendDecapsulationKey1024, error) { return xcrypto.GenerateKeyMLKEM1024() }
func newDecapsulationKey1024(seed []byte) (backendDecapsulationKey1024, error) {
	return xcrypto.NewDecapsulationKeyMLKEM1024(seed)
}
func newEncapsulationKey1024(encapsulationKey []byte) (backendEncapsulationKey1024, error) {
	return xcrypto.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
