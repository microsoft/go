package openssl_test

import (
	"bytes"
	"hash"
	"testing"

	"github.com/microsoft/go/pkg/openssl"
)

func TestHMAC(t *testing.T) {
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", openssl.NewSHA1},
		{"sha224", openssl.NewSHA224},
		{"sha256", openssl.NewSHA256},
		{"sha384", openssl.NewSHA384},
		{"sha512", openssl.NewSHA512},
		{"sha512_224", openssl.NewSHA512_224},
		{"sha512_256", openssl.NewSHA512_256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := openssl.NewHMAC(tt.fn, nil)
			if h == nil {
				t.Skip("digest not supported")
			}
			h.Write([]byte("hello"))
			sumHello := h.Sum(nil)

			h = openssl.NewHMAC(tt.fn, nil)
			h.Write([]byte("hello world"))
			sumHelloWorld := h.Sum(nil)

			// Test that Sum has no effect on future Sum or Write operations.
			// This is a bit unusual as far as usage, but it's allowed
			// by the definition of Go hash.Hash, and some clients expect it to work.
			h = openssl.NewHMAC(tt.fn, nil)
			h.Write([]byte("hello"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("1st Sum after hello = %x, want %x", sum, sumHello)
			}
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("2nd Sum after hello = %x, want %x", sum, sumHello)
			}

			h.Write([]byte(" world"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
				t.Fatalf("1st Sum after hello world = %x, want %x", sum, sumHelloWorld)
			}
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
				t.Fatalf("2nd Sum after hello world = %x, want %x", sum, sumHelloWorld)
			}

			h.Reset()
			h.Write([]byte("hello"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("Sum after Reset + hello = %x, want %x", sum, sumHello)
			}
		})
	}
}

func TestHMACUnsupportedHash(t *testing.T) {
	// Test that NewHMAC returns nil for unsupported hashes
	// instead of panicking.
	h := openssl.NewHMAC(newStubHash, nil)
	if h != nil {
		t.Errorf("returned non-nil for unsupported hash")
	}
}

func TestHMACAllocations(t *testing.T) {
	h := openssl.NewHMAC(openssl.NewSHA256, nil)
	msg := []byte("hello world")
	sum := make([]byte, openssl.NewSHA256().Size())
	n := int(testing.AllocsPerRun(10, func() {
		h.Write(msg)
		h.Sum(sum[:0])
		h.Reset()
	}))

	want := 2
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func BenchmarkHMACSHA256_32(b *testing.B) {
	b.StopTimer()
	key := make([]byte, 32)
	buf := make([]byte, 32)
	h := openssl.NewHMAC(openssl.NewSHA256, key)
	b.SetBytes(int64(len(buf)))
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
		mac := h.Sum(nil)
		h.Reset()
		buf[0] = mac[0]
	}
}

func BenchmarkHMACNewWriteSum(b *testing.B) {
	b.StopTimer()
	buf := make([]byte, 32)
	b.SetBytes(int64(len(buf)))
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := openssl.NewHMAC(openssl.NewSHA256, make([]byte, 32))
		h.Write(buf)
		mac := h.Sum(nil)
		buf[0] = mac[0]
	}
}
