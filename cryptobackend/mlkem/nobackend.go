// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package mlkem

type DecapsulationKey768 struct{}
type EncapsulationKey768 struct{}
type DecapsulationKey1024 struct{}
type EncapsulationKey1024 struct{}

func Supports768() bool                            { panic("cryptobackend: not available") }
func Supports1024() bool                           { panic("cryptobackend: not available") }
func GenerateKey768() (DecapsulationKey768, error) { panic("cryptobackend: not available") }
func NewDecapsulationKey768(seed []byte) (DecapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func NewEncapsulationKey768(encapsulationKey []byte) (EncapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func (dk DecapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (dk DecapsulationKey768) Decapsulate(ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (dk DecapsulationKey768) EncapsulationKey() EncapsulationKey768 {
	panic("cryptobackend: not available")
}
func (ek EncapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (ek EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}
func GenerateKey1024() (DecapsulationKey1024, error) { panic("cryptobackend: not available") }
func NewDecapsulationKey1024(seed []byte) (DecapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func NewEncapsulationKey1024(encapsulationKey []byte) (EncapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func (dk DecapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (dk DecapsulationKey1024) Decapsulate(ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (dk DecapsulationKey1024) EncapsulationKey() EncapsulationKey1024 {
	panic("cryptobackend: not available")
}
func (ek EncapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (ek EncapsulationKey1024) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}
