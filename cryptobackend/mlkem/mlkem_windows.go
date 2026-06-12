// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.systemcrypto

package mlkem

import "github.com/microsoft/go-crypto-winnative/cng"

type DecapsulationKey768 = cng.DecapsulationKeyMLKEM768
type EncapsulationKey768 = cng.EncapsulationKeyMLKEM768
type DecapsulationKey1024 = cng.DecapsulationKeyMLKEM1024
type EncapsulationKey1024 = cng.EncapsulationKeyMLKEM1024

func Supports768() bool                            { return cng.SupportsMLKEM() }
func Supports1024() bool                           { return cng.SupportsMLKEM() }
func GenerateKey768() (DecapsulationKey768, error) { return cng.GenerateKeyMLKEM768() }
func NewDecapsulationKey768(seed []byte) (DecapsulationKey768, error) {
	return cng.NewDecapsulationKeyMLKEM768(seed)
}
func NewEncapsulationKey768(encapsulationKey []byte) (EncapsulationKey768, error) {
	return cng.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func GenerateKey1024() (DecapsulationKey1024, error) { return cng.GenerateKeyMLKEM1024() }
func NewDecapsulationKey1024(seed []byte) (DecapsulationKey1024, error) {
	return cng.NewDecapsulationKeyMLKEM1024(seed)
}
func NewEncapsulationKey1024(encapsulationKey []byte) (EncapsulationKey1024, error) {
	return cng.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
