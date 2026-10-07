// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.systemcrypto

package mlkem

type backendDecapsulationKey768 struct{}
type backendEncapsulationKey768 struct{}
type backendDecapsulationKey1024 struct{}
type backendEncapsulationKey1024 struct{}

func Supports768() bool                                   { panic("cryptobackend: not available") }
func Supports1024() bool                                  { panic("cryptobackend: not available") }
func generateKey768() (backendDecapsulationKey768, error) { panic("cryptobackend: not available") }
func newDecapsulationKey768(seed []byte) (backendDecapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func newEncapsulationKey768(encapsulationKey []byte) (backendEncapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func (dk backendDecapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (dk backendDecapsulationKey768) Decapsulate(ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (dk backendDecapsulationKey768) EncapsulationKey() backendEncapsulationKey768 {
	panic("cryptobackend: not available")
}
func (ek backendEncapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (ek backendEncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}
func generateKey1024() (backendDecapsulationKey1024, error) { panic("cryptobackend: not available") }
func newDecapsulationKey1024(seed []byte) (backendDecapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func newEncapsulationKey1024(encapsulationKey []byte) (backendEncapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func (dk backendDecapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (dk backendDecapsulationKey1024) Decapsulate(ciphertext []byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (dk backendDecapsulationKey1024) EncapsulationKey() backendEncapsulationKey1024 {
	panic("cryptobackend: not available")
}
func (ek backendEncapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (ek backendEncapsulationKey1024) Encapsulate() (sharedKey, ciphertext []byte) {
	panic("cryptobackend: not available")
}
