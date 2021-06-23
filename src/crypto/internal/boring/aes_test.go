// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan
// +build cgo

package boring

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestNewGCMNonce(t *testing.T) {
	// Should return an error for non-standard nonce size.
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c := ci.(*aesCipher)
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize)
	if err == nil {
		t.Error("expected error for non-standard nonce size, got none")
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize-1)
	if err == nil {
		t.Error("expected error for non-standard tag size, got none")
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard tag / nonce size, got: %#v", err)
	}
}

func TestBlobEncryptBasicBlockEncryption(t *testing.T) {
	key := []byte{0x24, 0xcd, 0x8b, 0x13, 0x37, 0xc5, 0xc1, 0xb1, 0x0, 0xbb, 0x27, 0x40, 0x4f, 0xab, 0x5f, 0x7b, 0x2d, 0x0, 0x20, 0xf5, 0x1, 0x84, 0x4, 0xbf, 0xe3, 0xbd, 0xa1, 0xc4, 0xbf, 0x61, 0x2f, 0xc5}
	iv := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9, 0x79, 0xd5, 0xac, 0x74}

	block, err := NewAESCipher(key)
	if err != nil {
		t.Errorf("expected no error for aes.NewCipher, got: %s", err)
	}

	blockSize := block.BlockSize()
	if blockSize != 16 {
		t.Errorf("unexpected block size, expected 16 got: %d", blockSize)
	}
	var encryptor cipher.BlockMode
	if c, ok := block.(*aesCipher); ok {
		encryptor = c.NewCBCEncrypter(iv)
		if encryptor == nil {
			t.Error("unable to create new CBC encrypter")
		}
	}

	encrypted := make([]byte, 32)

	// First block. 16 bytes.
	srcBlock1 := bytes.Repeat([]byte{0x01}, 16)
	encryptor.CryptBlocks(encrypted, srcBlock1)
	if !bytes.Equal([]byte{
		0x14, 0xb7, 0x3e, 0x2f, 0xd9, 0xe7, 0x69, 0x7e, 0xb7, 0xd2, 0xc3, 0x5b, 0x31, 0x9c, 0xf0, 0x59,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, encrypted) {
		t.Error("unexpected CryptBlocks result for first block")
	}

	// Second block. 16 bytes.
	srcBlock2 := bytes.Repeat([]byte{0x02}, 16)
	encryptor.CryptBlocks(encrypted[16:], srcBlock2)
	if !bytes.Equal([]byte{
		0x14, 0xb7, 0x3e, 0x2f, 0xd9, 0xe7, 0x69, 0x7e, 0xb7, 0xd2, 0xc3, 0x5b, 0x31, 0x9c, 0xf0, 0x59,
		0xbb, 0xd4, 0x95, 0x25, 0x21, 0x56, 0x87, 0x3b, 0xe6, 0x22, 0xe8, 0xd0, 0x19, 0xa8, 0xed, 0xcd,
	}, encrypted) {
		t.Error("unexpected CryptBlocks result for second block")
	}
}
