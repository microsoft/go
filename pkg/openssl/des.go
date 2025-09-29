//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto/cipher"
	"errors"
)

// SupportsDESCipher returns true if NewDESCipher is supported,
// which uses ECB mode.
// If CBC is also supported, then the returned cipher.Block
// will also implement NewCBCEncrypter and NewCBCDecrypter.
func SupportsDESCipher() bool {
	// True for stock OpenSSL 1 w/o FIPS.
	// False for stock OpenSSL 3 unless the legacy provider is available.
	return (versionAtOrAbove(3, 0, 0) || !FIPS()) && loadCipher(cipherDES, cipherModeECB) != nil
}

// SupportsTripleDESCipher returns true if NewTripleDESCipher is supported,
// which uses ECB mode.
// If CBC is also supported, then the returned cipher.Block
// will also implement NewCBCEncrypter and NewCBCDecrypter.
func SupportsTripleDESCipher() bool {
	// Should always be true for stock OpenSSL,
	// even when using the FIPS provider.
	return loadCipher(cipherDES3, cipherModeECB) != nil
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, errors.New("crypto/des: invalid key size")
	}
	return newDESCipher(key, cipherDES)
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, errors.New("crypto/des: invalid key size")
	}
	return newDESCipher(key, cipherDES3)
}

func newDESCipher(key []byte, kind cipherKind) (cipher.Block, error) {
	c, err := newEVPCipher(key, kind)
	if err != nil {
		return nil, err
	}
	if loadCipher(kind, cipherModeCBC) == nil {
		return &desCipherWithoutCBC{c}, nil
	}
	return &desCipher{c}, nil
}

type desExtraModes interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}

var _ desExtraModes = (*desCipher)(nil)

type desCipher struct {
	*evpCipher
}

func (c *desCipher) BlockSize() int {
	return c.blockSize
}

func (c *desCipher) Encrypt(dst, src []byte) {
	if err := c.encrypt(dst, src); err != nil {
		// crypto/des expects that the panic message starts with "crypto/des: ".
		panic("crypto/des: " + err.Error())
	}
}

func (c *desCipher) Decrypt(dst, src []byte) {
	if err := c.decrypt(dst, src); err != nil {
		// crypto/des expects that the panic message starts with "crypto/des: ".
		panic("crypto/des: " + err.Error())
	}
}

func (c *desCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, cipherOpEncrypt)
}

func (c *desCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, cipherOpDecrypt)
}

type desCipherWithoutCBC struct {
	*evpCipher
}

func (c *desCipherWithoutCBC) BlockSize() int {
	return c.blockSize
}

func (c *desCipherWithoutCBC) Encrypt(dst, src []byte) {
	if err := c.encrypt(dst, src); err != nil {
		// crypto/des expects that the panic message starts with "crypto/des: ".
		panic("crypto/des: " + err.Error())
	}
}

func (c *desCipherWithoutCBC) Decrypt(dst, src []byte) {
	if err := c.decrypt(dst, src); err != nil {
		// crypto/des expects that the panic message starts with "crypto/des: ".
		panic("crypto/des: " + err.Error())
	}
}
