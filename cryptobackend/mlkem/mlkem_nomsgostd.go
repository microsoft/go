// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !msgostd && !cmd_go_bootstrap

package mlkem

// Standalone builds and source importers need declarations that do not import
// standard-library internals.
type fipsDecapsulationKey768 struct{}
type fipsEncapsulationKey768 struct{}
type fipsDecapsulationKey1024 struct{}
type fipsEncapsulationKey1024 struct{}

func (*fipsDecapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (*fipsDecapsulationKey768) Decapsulate([]byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (*fipsDecapsulationKey768) EncapsulationKey() *fipsEncapsulationKey768 {
	panic("cryptobackend: not available")
}
func (*fipsEncapsulationKey768) Bytes() []byte { panic("cryptobackend: not available") }
func (*fipsEncapsulationKey768) Encapsulate() ([]byte, []byte) {
	panic("cryptobackend: not available")
}
func (*fipsDecapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (*fipsDecapsulationKey1024) Decapsulate([]byte) ([]byte, error) {
	panic("cryptobackend: not available")
}
func (*fipsDecapsulationKey1024) EncapsulationKey() *fipsEncapsulationKey1024 {
	panic("cryptobackend: not available")
}
func (*fipsEncapsulationKey1024) Bytes() []byte { panic("cryptobackend: not available") }
func (*fipsEncapsulationKey1024) Encapsulate() ([]byte, []byte) {
	panic("cryptobackend: not available")
}

func GenerateKey768() (*DecapsulationKey768, error)   { panic("cryptobackend: not available") }
func GenerateKey1024() (*DecapsulationKey1024, error) { panic("cryptobackend: not available") }
func NewDecapsulationKey768([]byte) (*DecapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func NewDecapsulationKey1024([]byte) (*DecapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func NewEncapsulationKey768([]byte) (*EncapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func NewEncapsulationKey1024([]byte) (*EncapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
func defaultRandomReader() bool { panic("cryptobackend: not available") }
func newGoEncapsulationKey768([]byte) (*fipsEncapsulationKey768, error) {
	panic("cryptobackend: not available")
}
func newGoEncapsulationKey1024([]byte) (*fipsEncapsulationKey1024, error) {
	panic("cryptobackend: not available")
}
