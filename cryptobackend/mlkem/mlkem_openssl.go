// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.opensslcrypto

package mlkem

import "github.com/microsoft/go-crypto-openssl/openssl"

type backendDecapsulationKey768 = openssl.DecapsulationKeyMLKEM768
type backendEncapsulationKey768 = openssl.EncapsulationKeyMLKEM768
type backendDecapsulationKey1024 = openssl.DecapsulationKeyMLKEM1024
type backendEncapsulationKey1024 = openssl.EncapsulationKeyMLKEM1024

func Supports768() bool                                   { return openssl.SupportsMLKEM768() }
func Supports1024() bool                                  { return openssl.SupportsMLKEM1024() }
func generateKey768() (backendDecapsulationKey768, error) { return openssl.GenerateKeyMLKEM768() }
func newDecapsulationKey768(seed []byte) (backendDecapsulationKey768, error) {
	return openssl.NewDecapsulationKeyMLKEM768(seed)
}
func newEncapsulationKey768(encapsulationKey []byte) (backendEncapsulationKey768, error) {
	return openssl.NewEncapsulationKeyMLKEM768(encapsulationKey)
}
func generateKey1024() (backendDecapsulationKey1024, error) { return openssl.GenerateKeyMLKEM1024() }
func newDecapsulationKey1024(seed []byte) (backendDecapsulationKey1024, error) {
	return openssl.NewDecapsulationKeyMLKEM1024(seed)
}
func newEncapsulationKey1024(encapsulationKey []byte) (backendEncapsulationKey1024, error) {
	return openssl.NewEncapsulationKeyMLKEM1024(encapsulationKey)
}
