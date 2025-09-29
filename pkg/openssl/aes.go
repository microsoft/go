//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto/cipher"
	"errors"
)

//go:generate go run github.com/microsoft/go/pkg/openssl/cmd/genaesmodes -in aes.go -modes CBC,CTR,GCM -out zaes.go
//go:generate go run github.com/microsoft/go/pkg/openssl/cmd/gentestvectors -out vectors_test.go

// Steps to support a new AES mode, e.g. `FOO`:
// 1. Add `FOO` to the list of modes in the `genaesmodes` command.
// 2. Run `go generate` to update the generated code.
// 3. Implement the necessary interfaces for the new struct, which will be named `cipherWithFOO`.

// NewAESCipher creates and returns a new AES cipher.Block.
// The key argument should be the AES key, either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
// The returned cipher.Block implements the CBC, CTR, and/or GCM modes if
// the underlying OpenSSL library supports them.
func NewAESCipher(key []byte) (cipher.Block, error) {
	var kind cipherKind
	switch len(key) * 8 {
	case 128:
		kind = cipherAES128
	case 192:
		kind = cipherAES192
	case 256:
		kind = cipherAES256
	default:
		return nil, errors.New("crypto/aes: invalid key size")
	}
	c, err := newEVPCipher(key, kind)
	if err != nil {
		return nil, err
	}
	return newAESBlock(c, kind), nil
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	if c, ok := c.(interface {
		NewGCMTLS() (cipher.AEAD, error)
	}); ok {
		return c.NewGCMTLS()
	}
	return nil, errors.New("GCM not supported")
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	if c, ok := c.(interface {
		NewGCMTLS13() (cipher.AEAD, error)
	}); ok {
		return c.NewGCMTLS13()
	}
	return nil, errors.New("GCM not supported")
}

// aesCipher implements the cipher.Block interface.
type aesCipher struct {
	cipher *evpCipher
}

func (c aesCipher) BlockSize() int {
	return c.cipher.blockSize
}

func (c aesCipher) Encrypt(dst, src []byte) {
	if err := c.cipher.encrypt(dst, src); err != nil {
		// crypto/aes expects that the panic message starts with "crypto/aes: ".
		panic("crypto/aes: " + err.Error())
	}
}

func (c aesCipher) Decrypt(dst, src []byte) {
	if err := c.cipher.decrypt(dst, src); err != nil {
		// crypto/aes expects that the panic message starts with "crypto/aes: ".
		panic("crypto/aes: " + err.Error())
	}
}

// Implement optional interfaces for AES modes.

func (c cipherWithCBC) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.cipher.newCBC(iv, cipherOpEncrypt)
}

func (c cipherWithCBC) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.cipher.newCBC(iv, cipherOpDecrypt)
}

func (c cipherWithCTR) NewCTR(iv []byte) cipher.Stream {
	return c.cipher.newCTR(iv)
}

func (c cipherWithGCM) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	return c.cipher.newGCMChecked(nonceSize, tagSize)
}

func (c cipherWithGCM) NewGCMTLS() (cipher.AEAD, error) {
	return c.cipher.newGCM(cipherGCMTLS12)
}

func (c cipherWithGCM) NewGCMTLS13() (cipher.AEAD, error) {
	return c.cipher.newGCM(cipherGCMTLS13)
}

// The following interfaces have been copied out of crypto/aes/modes.go.

type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
}

type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}

type ctrAble interface {
	NewCTR(iv []byte) cipher.Stream
}

// Test that the interfaces are implemented.

var (
	_ cipher.Block = (*aesCipher)(nil)

	_ cipher.Block = (*cipherWithCBC)(nil)
	_ cbcEncAble   = (*cipherWithCBC)(nil)
	_ cbcDecAble   = (*cipherWithCBC)(nil)

	_ cipher.Block = (*cipherWithCTR)(nil)
	_ ctrAble      = (*cipherWithCTR)(nil)

	_ cipher.Block = (*cipherWithGCM)(nil)
	_ gcmAble      = (*cipherWithGCM)(nil)
)
