// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package mlkem

import "github.com/microsoft/go-crypto-openssl/openssl"

type DecapsulationKey768 = openssl.DecapsulationKeyMLKEM768
type EncapsulationKey768 = openssl.EncapsulationKeyMLKEM768
type DecapsulationKey1024 = openssl.DecapsulationKeyMLKEM1024
type EncapsulationKey1024 = openssl.EncapsulationKeyMLKEM1024

func Supports768() bool                            { return openssl.SupportsMLKEM768() }
func Supports1024() bool                           { return openssl.SupportsMLKEM1024() }
func GenerateKey768() (DecapsulationKey768, error) { return openssl.GenerateKeyMLKEM768() }
func NewDecapsulationKey768(seed []byte) (DecapsulationKey768, error) {
	return openssl.NewDecapsulationKeyMLKEM768(seed)
}
func NewEncapsulationKey768(encapsulationKey []byte) (EncapsulationKey768, error) {
	return openssl.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func GenerateKey1024() (DecapsulationKey1024, error) { return openssl.GenerateKeyMLKEM1024() }
func NewDecapsulationKey1024(seed []byte) (DecapsulationKey1024, error) {
	return openssl.NewDecapsulationKeyMLKEM1024(seed)
}
func NewEncapsulationKey1024(encapsulationKey []byte) (EncapsulationKey1024, error) {
	return openssl.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
