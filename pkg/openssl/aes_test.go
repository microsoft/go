package openssl_test

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"math"
	"testing"

	"github.com/microsoft/go/pkg/openssl"
	"github.com/microsoft/go/pkg/openssl/internal/cryptotest"
)

// Test AES against the general cipher.Block interface tester.
func TestAESBlock(t *testing.T) {
	for _, keylen := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("AES-%d", keylen), func(t *testing.T) {
			cryptotest.TestBlock(t, keylen/8, openssl.NewAESCipher)
		})
	}
}

func TestNewGCMNonce(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	const (
		gcmTagSize           = 16
		gcmStandardNonceSize = 12
	)

	c, ok := ci.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	})
	if !ok {
		t.Fatal("cipher does not support NewGCM")
	}
	g, err := c.NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard nonce size with standard tag size, got: %#v", err)
	}
	if g.NonceSize() != gcmStandardNonceSize {
		t.Errorf("unexpected nonce size\ngot: %#v\nexp: %#v",
			g.NonceSize(), gcmStandardNonceSize)
	}
	if g.Overhead() != gcmTagSize {
		t.Errorf("unexpected tag size\ngot: %#v\nexp: %#v",
			g.Overhead(), gcmTagSize)
	}

	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize-1)
	if err == nil {
		t.Error("expected error for non-standard tag and nonce size at the same time, got none")
	}
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for non-standard nonce size with standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize-1)
	if err != nil {
		t.Errorf("expected no error for standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard tag / nonce size, got: %#v", err)
	}
}

func TestSealAndOpen(t *testing.T) {
	for _, tt := range aesGCMTests {
		t.Run(tt.description, func(t *testing.T) {
			ci, err := openssl.NewAESCipher(tt.key)
			if err != nil {
				t.Fatalf("NewAESCipher() err = %v", err)
			}
			gcm, err := cipher.NewGCM(ci)
			if err != nil {
				t.Fatalf("cipher.NewGCM() err = %v", err)
			}

			sealed := gcm.Seal(nil, tt.nonce, tt.plaintext, tt.aad)
			if !bytes.Equal(sealed, tt.ciphertext) {
				t.Errorf("unexpected sealed result\ngot: %#v\nexp: %#v", sealed, tt.ciphertext)
			}

			decrypted, err := gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != nil {
				t.Errorf("gcm.Open() err = %v", err)
			}
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, tt.plaintext)
			}

			// Test that open fails if the ciphertext is modified.
			tt.ciphertext[0] ^= 0x80
			_, err = gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != openssl.ErrOpen {
				t.Errorf("expected authentication error for tampered message\ngot: %#v", err)
			}
			tt.ciphertext[0] ^= 0x80

			// Test that the ciphertext can be opened using a fresh context
			// which was not previously used to seal the same message.
			gcm, err = cipher.NewGCM(ci)
			if err != nil {
				t.Fatalf("cipher.NewGCM() err = %v", err)
			}
			decrypted, err = gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != nil {
				t.Errorf("fresh GCM instance: gcm.Open() err = %v", err)
			}
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("fresh GCM instance: unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSealAndOpen_Empty(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	sealed := gcm.Seal(nil, nonce, []byte{}, []byte{})
	decrypted, err := gcm.Open(nil, nonce, sealed, []byte{})
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, []byte{}) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, []byte{})
	}
}

func TestSealAndOpenTLS(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	tests := []struct {
		name string
		tls  string
		mask func(n *[12]byte)
	}{
		{"1.2", "1.2", nil},
		{"1.3", "1.3", nil},
		{"1.3_masked", "1.3", func(n *[12]byte) {
			// Arbitrary mask in the high bits.
			n[9] ^= 0x42
			// Mask the very first bit. This makes sure that if Seal doesn't
			// handle the mask, the counter appears to go backwards and panics
			// when it shouldn't.
			n[11] ^= 0x1
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci, err := openssl.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			var gcm cipher.AEAD
			switch tt.tls {
			case "1.2":
				gcm, err = openssl.NewGCMTLS(ci)
			case "1.3":
				gcm, err = openssl.NewGCMTLS13(ci)
			}
			if err != nil {
				t.Fatal(err)
			}
			nonce := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			nonce1 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
			nonce9 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
			nonce10 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
			nonceMax := [12]byte{0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255}
			if tt.mask != nil {
				for _, m := range []*[12]byte{&nonce, &nonce1, &nonce9, &nonce10, &nonceMax} {
					tt.mask(m)
				}
			}
			plainText := []byte{0x01, 0x02, 0x03}
			var additionalData []byte
			switch tt.tls {
			case "1.2":
				additionalData = make([]byte, 13)
			case "1.3":
				additionalData = []byte{23, 3, 3, 0, 0}
			}
			additionalData[len(additionalData)-2] = byte(len(plainText) >> 8)
			additionalData[len(additionalData)-1] = byte(len(plainText))
			sealed := gcm.Seal(nil, nonce[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce[:], plainText, additionalData)
			})
			sealed1 := gcm.Seal(nil, nonce1[:], plainText, additionalData)
			gcm.Seal(nil, nonce10[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce9[:], plainText, additionalData)
			})
			assertPanic(t, func() {
				gcm.Seal(nil, nonceMax[:], plainText, additionalData)
			})
			if bytes.Equal(sealed, sealed1) {
				t.Errorf("different nonces should produce different outputs\ngot: %#v\nexp: %#v", sealed, sealed1)
			}
			decrypted, err := gcm.Open(nil, nonce[:], sealed, additionalData)
			if err != nil {
				t.Error(err)
			}
			decrypted1, err := gcm.Open(nil, nonce1[:], sealed1, additionalData)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(decrypted, plainText) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
			}
			if !bytes.Equal(decrypted, decrypted1) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, decrypted1)
			}
		})
	}
}

func TestSealAndOpenAuthenticationError(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	plainText := []byte{0x01, 0x02, 0x03}
	additionalData := []byte{0x05, 0x05, 0x07}
	sealed := gcm.Seal(nil, nonce, plainText, additionalData)
	_, err = gcm.Open(nil, nonce, sealed, nil)
	if err != openssl.ErrOpen {
		t.Errorf("expected authentication error, got: %#v", err)
	}
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}

func TestSealPanic(t *testing.T) {
	ci, err := openssl.NewAESCipher([]byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D"))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		t.Fatal(err)
	}
	assertPanic(t, func() {
		gcm.Seal(nil, make([]byte, gcm.NonceSize()-1), []byte{0x01, 0x02, 0x03}, nil)
	})
	assertPanic(t, func() {
		gcm.Seal(nil, make([]byte, gcm.NonceSize()), make([]byte, math.MaxInt), nil)
	})
}

func TestBlobEncryptBasicBlockEncryption(t *testing.T) {
	key := []byte{0x24, 0xcd, 0x8b, 0x13, 0x37, 0xc5, 0xc1, 0xb1, 0x0, 0xbb, 0x27, 0x40, 0x4f, 0xab, 0x5f, 0x7b, 0x2d, 0x0, 0x20, 0xf5, 0x1, 0x84, 0x4, 0xbf, 0xe3, 0xbd, 0xa1, 0xc4, 0xbf, 0x61, 0x2f, 0xc5}
	iv := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9, 0x79, 0xd5, 0xac, 0x74}

	block, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Errorf("expected no error for aes.NewCipher, got: %s", err)
	}

	blockSize := block.BlockSize()
	if blockSize != 16 {
		t.Errorf("unexpected block size, expected 16 got: %d", blockSize)
	}
	encryptor := cipher.NewCBCEncrypter(block, iv)
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

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plainText := append(srcBlock1, srcBlock2...)
	decrypted := make([]byte, len(plainText))
	decrypter.CryptBlocks(decrypted, encrypted[:16])
	decrypter.CryptBlocks(decrypted[16:], encrypted[16:])
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}

func testDecrypt(t *testing.T, resetNonce bool) {
	key := []byte{
		0x24, 0xcd, 0x8b, 0x13, 0x37, 0xc5, 0xc1, 0xb1,
		0x0, 0xbb, 0x27, 0x40, 0x4f, 0xab, 0x5f, 0x7b,
		0x2d, 0x0, 0x20, 0xf5, 0x1, 0x84, 0x4, 0xbf,
		0xe3, 0xbd, 0xa1, 0xc4, 0xbf, 0x61, 0x2f, 0xc5,
	}

	block, err := openssl.NewAESCipher(key)
	if err != nil {
		panic(err)
	}

	iv := []byte{
		0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb,
		0x91, 0xa8, 0x6c, 0xf9, 0x79, 0xd5, 0xac, 0x74,
	}
	encrypter := cipher.NewCBCEncrypter(block, iv)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	if resetNonce {
		for i := range iv {
			iv[i] = 0
		}
	}

	plainText := []byte{
		0x54, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73,
		0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x6f,
		0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x52, 0x69,
		0x6e, 0x67, 0x2c, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
		0x20, 0x6f, 0x6e, 0x65, 0x20, 0x77, 0x68, 0x6f,
		0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x6e,
		0x64, 0x20, 0x69, 0x74, 0x20, 0x74, 0x6f, 0x20,
		0x68, 0x69, 0x73, 0x20, 0x77, 0x69, 0x6c, 0x6c,
		0x2e, 0x20, 0x41, 0x6e, 0x64, 0x20, 0x68, 0x65,
		0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f,
		0x74, 0x20, 0x73, 0x68, 0x61, 0x72, 0x65, 0x20,
		0x70, 0x6f, 0x77, 0x65, 0x72, 0x2e, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	cipherText := make([]byte, len(plainText))

	encrypter.CryptBlocks(cipherText, plainText[:64])
	encrypter.CryptBlocks(cipherText[64:], plainText[64:])

	expectedCipherText := []byte{
		23, 51, 192, 210, 170, 124, 30, 218,
		176, 54, 70, 132, 141, 124, 3, 152,
		47, 3, 37, 81, 187, 101, 197, 94,
		11, 38, 128, 60, 112, 20, 235, 130,
		111, 236, 176, 99, 121, 6, 221, 181,
		190, 228, 150, 177, 218, 3, 196, 0,
		5, 141, 169, 151, 3, 161, 64, 244,
		231, 237, 252, 143, 111, 37, 68, 70,
		11, 137, 220, 243, 195, 90, 182, 83,
		96, 80, 122, 14, 93, 178, 62, 159,
		25, 162, 200, 155, 21, 150, 6, 101,
		21, 234, 12, 74, 190, 213, 159, 220,
		111, 184, 94, 169, 188, 93, 38, 150,
		3, 208, 185, 201, 212, 246, 238, 181,
	}
	if !bytes.Equal(expectedCipherText, cipherText) {
		t.Fail()
	}

	decrypted := make([]byte, len(plainText))

	decrypter.CryptBlocks(decrypted, cipherText[:64])
	decrypter.CryptBlocks(decrypted[64:], cipherText[64:])

	if len(decrypted) != len(plainText) {
		t.Fail()
	}

	if !bytes.Equal(plainText, decrypted) {
		t.Errorf("decryption incorrect\nexp %v, got %v\n", plainText, decrypted)
	}
}

func TestDecryptSimple(t *testing.T) {
	testDecrypt(t, false)
}

func TestDecryptInvariantReusableNonce(t *testing.T) {
	// Test that changing the iv slice after creating the encrypter
	// and decrypter doesn't change the encrypter/decrypter state."
	testDecrypt(t, true)
}

func TestCipherEncryptDecrypt(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	pt := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	c, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(pt))
	c.Encrypt(ct, pt)

	pt2 := make([]byte, len(pt))
	c.Decrypt(pt2, ct)

	if !bytes.Equal(pt2, pt) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", pt2, pt)
	}
}

func TestNewCTR(t *testing.T) {
	// AES-128-CTR test vector (NIST SP 800-38A pp 55-58)
	// Copied from crypto/cipher/common_test.go
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	counter := []byte{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
	input := []byte{
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
	}
	output := []byte{
		0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
		0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
		0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
		0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
	}
	c, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j <= 5; j += 5 {
		pt := input[0 : len(input)-j]
		ctr := cipher.NewCTR(c, counter)
		ct := make([]byte, len(pt))
		ctr.XORKeyStream(ct, pt)
		if out := output[0:len(pt)]; !bytes.Equal(out, ct) {
			t.Errorf("CTR\ninpt %x\nhave %x\nwant %x", pt, ct, out)
		}
	}
}

func TestCipherEncryptDecryptSharedBuffer(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	pt := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	c, err := openssl.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	b := append(pt, make([]byte, len(pt))...)
	// Keep b's length for the shared-buffer plaintext.
	// This test verifies that Encrypt and Decrypt only check for overlap in the
	// first block-length of the args, matching Go standard library behavior.
	bPt := b
	bCt := b[len(pt):]
	c.Encrypt(bCt, bPt)
	c.Decrypt(bPt, bCt)
}

func BenchmarkAES_Encrypt(b *testing.B) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	in := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	c, err := openssl.NewAESCipher(key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(in))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, in)
	}
}

func BenchmarkAES_Decrypt(b *testing.B) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	in := []byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32}
	c, err := openssl.NewAESCipher(key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(in))
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, in)
	}
}

func BenchmarkAESGCM_Open(b *testing.B) {
	const length = 64
	const keySize = 128 / 8
	buf := make([]byte, length)

	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	var nonce [12]byte
	var ad [13]byte
	c, _ := openssl.NewAESCipher(key)
	aesgcm, _ := cipher.NewGCM(c)
	var out []byte

	ct := aesgcm.Seal(nil, nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = aesgcm.Open(out[:0], nonce[:], ct, ad[:])
	}
}

func BenchmarkAESGCM_Seal(b *testing.B) {
	const length = 64
	const keySize = 128 / 8
	buf := make([]byte, length)

	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	var nonce [12]byte
	var ad [13]byte
	c, _ := openssl.NewAESCipher(key)
	aesgcm, _ := cipher.NewGCM(c)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}
