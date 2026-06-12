// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mlkem

import "github.com/microsoft/go-crypto-darwin/xcrypto"

type DecapsulationKey768 = xcrypto.DecapsulationKeyMLKEM768
type EncapsulationKey768 = xcrypto.EncapsulationKeyMLKEM768
type DecapsulationKey1024 = xcrypto.DecapsulationKeyMLKEM1024
type EncapsulationKey1024 = xcrypto.EncapsulationKeyMLKEM1024

func Supports768() bool                            { return xcrypto.SupportsMLKEM() }
func Supports1024() bool                           { return xcrypto.SupportsMLKEM() }
func GenerateKey768() (DecapsulationKey768, error) { return xcrypto.GenerateKeyMLKEM768() }
func NewDecapsulationKey768(seed []byte) (DecapsulationKey768, error) {
	return xcrypto.NewDecapsulationKeyMLKEM768(seed)
}
func NewEncapsulationKey768(encapsulationKey []byte) (EncapsulationKey768, error) {
	return xcrypto.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func GenerateKey1024() (DecapsulationKey1024, error) { return xcrypto.GenerateKeyMLKEM1024() }
func NewDecapsulationKey1024(seed []byte) (DecapsulationKey1024, error) {
	return xcrypto.NewDecapsulationKeyMLKEM1024(seed)
}
func NewEncapsulationKey1024(encapsulationKey []byte) (EncapsulationKey1024, error) {
	return xcrypto.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
