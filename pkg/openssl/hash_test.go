package openssl_test

import (
	"bytes"
	"crypto"
	"encoding"
	"errors"
	"hash"
	"io"
	"runtime"
	"strings"
	"testing"

	// Blank imports to ensure that the hash functions are registered.
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/microsoft/go/pkg/openssl"
)

func cryptoToHash(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.MD4:
		return openssl.NewMD4
	case crypto.MD5:
		return openssl.NewMD5
	case crypto.SHA1:
		return openssl.NewSHA1
	case crypto.SHA224:
		return openssl.NewSHA224
	case crypto.SHA256:
		return openssl.NewSHA256
	case crypto.SHA384:
		return openssl.NewSHA384
	case crypto.SHA512:
		return openssl.NewSHA512
	case crypto.SHA512_224:
		return openssl.NewSHA512_224
	case crypto.SHA512_256:
		return openssl.NewSHA512_256
	case crypto.SHA3_224:
		return openssl.NewSHA3_224
	case crypto.SHA3_256:
		return openssl.NewSHA3_256
	case crypto.SHA3_384:
		return openssl.NewSHA3_384
	case crypto.SHA3_512:
		return openssl.NewSHA3_512
	}
	return nil
}

var hashes = [...]crypto.Hash{
	crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.SHA512_224,
	crypto.SHA512_256,
	crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_384,
	crypto.SHA3_512,
}

func TestHash(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)()
			initSum := h.Sum(nil)
			n, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(msg) {
				t.Errorf("got: %d, want: %d", n, len(msg))
			}
			sum := h.Sum(nil)
			if size := h.Size(); len(sum) != size {
				t.Errorf("got: %d, want: %d", len(sum), size)
			}
			if bytes.Equal(sum, initSum) {
				t.Error("Write didn't change internal hash state")
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

type hashEncoding interface {
	hash.Hash
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type hashEncodingAppender interface {
	hashEncoding
	AppendBinary(b []byte) ([]byte, error)
}

func TestHash_BinaryMarshaler(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("hash not supported")
			}

			hashMarshaler, ok := cryptoToHash(ch)().(hashEncoding)
			if !ok {
				t.Fatal("BinaryMarshaler not supported")
			}

			if _, err := hashMarshaler.Write(msg); err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			state, err := hashMarshaler.MarshalBinary()
			if err != nil {
				if strings.Contains(err.Error(), "hash state is not marshallable") {
					t.Skip("BinaryMarshaler not supported")
				}
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			hashUnmarshaler := cryptoToHash(ch)().(hashEncoding)
			if err := hashUnmarshaler.UnmarshalBinary(state); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}

			if actual, actual2 := hashMarshaler.Sum(nil), hashUnmarshaler.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != appended 0x%x", actual, actual2)
			}

			// Test that the hash state is compatible with native Go.
			h, ok := ch.New().(hashEncoding)
			if !ok {
				// The standard library doesn't support encoding this hash.
				// Nothing else to do.
				return
			}
			h.Write(msg)
			stateh, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(state, stateh) {
				t.Errorf("got 0x%x != want 0x%x", state, stateh)
			}
			h = ch.New().(hashEncoding)
			if err := h.UnmarshalBinary(state); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHash_BinaryAppender(t *testing.T) {
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("not supported")
			}

			hashWithBinaryAppender, ok := cryptoToHash(ch)().(hashEncodingAppender)
			if !ok {
				t.Fatal("AppendBinary not supported")
			}

			// Create a slice with 10 elements
			prebuiltSlice := make([]byte, 10)
			// Fill the slice with some data
			for i := range prebuiltSlice {
				prebuiltSlice[i] = byte(i)
			}

			// Clone the prebuilt slice for comparison
			prebuiltSliceClone := append([]byte(nil), prebuiltSlice...)

			// Append binary data to the prebuilt slice
			state, err := hashWithBinaryAppender.AppendBinary(prebuiltSlice)
			if err != nil {
				if errors.Is(err, errors.ErrUnsupported) {
					t.Skip("AppendBinary not supported")
				}
				t.Errorf("could not append binary: %v", err)
			}

			// Ensure the first 10 elements are still the same
			if !bytes.Equal(state[:10], prebuiltSliceClone) {
				t.Errorf("prebuilt slice modified: got %v, want %v", state[:10], prebuiltSliceClone)
			}

			// Use only the newly appended part of the slice
			appendedState := state[10:]

			h2, ok := cryptoToHash(ch)().(hashEncoding)
			if !ok {
				t.Skip("not supported")
			}

			if err := h2.UnmarshalBinary(appendedState); err != nil {
				t.Errorf("could not unmarshal: %v", err)
			}
			if actual, actual2 := hashWithBinaryAppender.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != appended 0x%x", actual, actual2)
			}
		})
	}
}

func TestHash_Clone(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)().(openssl.HashCloner)
			_, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}

			h3, err := h.Clone()
			if err != nil {
				t.Fatalf("Clone failed: %v", err)
			}
			prefix := []byte("tmp")
			writeToHash(t, h, prefix)
			h2, err := h.Clone()
			if err != nil {
				t.Fatalf("Clone failed: %v", err)
			}
			prefixSum := h.Sum(nil)
			if !bytes.Equal(prefixSum, h2.Sum(nil)) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			suffix := []byte("tmp2")
			writeToHash(t, h, suffix)
			writeToHash(t, h3, append(prefix, suffix...))
			compositeSum := h3.Sum(nil)
			if !bytes.Equal(h.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			if !bytes.Equal(h2.Sum(nil), prefixSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			writeToHash(t, h2, suffix)
			if !bytes.Equal(h.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
			if !bytes.Equal(h2.Sum(nil), compositeSum) {
				t.Fatalf("%T Clone results are inconsistent", h)
			}
		})
	}
}

func TestHash_ByteWriter(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("not supported")
			}
			bwh := cryptoToHash(ch)().(interface {
				hash.Hash
				io.ByteWriter
			})
			initSum := bwh.Sum(nil)
			for i := range len(msg) {
				bwh.WriteByte(msg[i])
			}
			bwh.Reset()
			sum := bwh.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_StringWriter(t *testing.T) {
	msg := []byte("testing")
	for _, ch := range hashes {
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("not supported")
			}
			h := cryptoToHash(ch)()
			initSum := h.Sum(nil)
			h.(io.StringWriter).WriteString("")
			h.(io.StringWriter).WriteString(string(msg))
			h.Reset()
			sum := h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		h       crypto.Hash
		oneShot func([]byte) []byte
	}{
		{crypto.SHA1, func(p []byte) []byte {
			b := openssl.SHA1(p)
			return b[:]
		}},
		{crypto.SHA224, func(p []byte) []byte {
			b := openssl.SHA224(p)
			return b[:]
		}},
		{crypto.SHA256, func(p []byte) []byte {
			b := openssl.SHA256(p)
			return b[:]
		}},
		{crypto.SHA384, func(p []byte) []byte {
			b := openssl.SHA384(p)
			return b[:]
		}},
		{crypto.SHA512, func(p []byte) []byte {
			b := openssl.SHA512(p)
			return b[:]
		}},
		{crypto.SHA512_224, func(p []byte) []byte {
			b := openssl.SHA512_224(p)
			return b[:]
		}},
		{crypto.SHA512_256, func(p []byte) []byte {
			b := openssl.SHA512_256(p)
			return b[:]
		}},
		{crypto.SHA3_224, func(p []byte) []byte {
			b := openssl.SHA3_224(p)
			return b[:]
		}},
		{crypto.SHA3_256, func(p []byte) []byte {
			b := openssl.SHA3_256(p)
			return b[:]
		}},
		{crypto.SHA3_384, func(p []byte) []byte {
			b := openssl.SHA3_384(p)
			return b[:]
		}},
		{crypto.SHA3_512, func(p []byte) []byte {
			b := openssl.SHA3_512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.h.String(), func(t *testing.T) {
			if !openssl.SupportsHash(tt.h) {
				t.Skip("not supported")
			}
			_ = tt.oneShot(nil) // test that does not panic
			got := tt.oneShot(msg)
			h := cryptoToHash(tt.h)()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

type cgoData struct {
	Data [16]byte
	Ptr  *cgoData
}

func TestCgo(t *testing.T) {
	// Test that Write does not cause cgo to scan the entire cgoData struct for pointers.
	// The scan (if any) should be limited to the [16]byte.
	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()
	d := new(cgoData)
	d.Ptr = d
	h := openssl.NewSHA256()
	h.Write(d.Data[:])
	h.Sum(nil)

	openssl.SHA256(d.Data[:])
}

func verifySHA256(token, salt string) [32]byte {
	return openssl.SHA256([]byte(token + salt))
}

func TestIssue71943(t *testing.T) {
	// https://github.com/golang/go/issues/71943
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	n := int(testing.AllocsPerRun(10, func() {
		runtime.KeepAlive(verifySHA256("teststring", "test"))
	}))
	want := 2
	if compareCurrentVersion("go1.25") >= 0 {
		want = 0
	} else if compareCurrentVersion("go1.24") >= 0 {
		want = 1
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")
	n := int(testing.AllocsPerRun(10, func() {
		sink ^= openssl.SHA1(msg)[0]
		sink ^= openssl.SHA224(msg)[0]
		sink ^= openssl.SHA256(msg)[0]
		sink ^= openssl.SHA512(msg)[0]
	}))
	want := 4
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashStructAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	msg := []byte("testing")

	sha1Hash := openssl.NewSHA1()
	sha224Hash := openssl.NewSHA1()
	sha256Hash := openssl.NewSHA256()
	sha512Hash := openssl.NewSHA512()

	sum := make([]byte, sha512Hash.Size())
	n := int(testing.AllocsPerRun(10, func() {
		sha1Hash.Write(msg)
		sha224Hash.Write(msg)
		sha256Hash.Write(msg)
		sha512Hash.Write(msg)

		sha1Hash.Sum(sum[:0])
		sha224Hash.Sum(sum[:0])
		sha256Hash.Sum(sum[:0])
		sha512Hash.Sum(sum[:0])

		sha1Hash.Reset()
		sha224Hash.Reset()
		sha256Hash.Reset()
		sha512Hash.Reset()
	}))
	want := 4
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func BenchmarkSHA256(b *testing.B) {
	b.StopTimer()
	h := openssl.NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256OneShot(b *testing.B) {
	b.StopTimer()
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		openssl.SHA256(buf)
	}
}

func BenchmarkNewSHA256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		openssl.NewSHA256()
	}
}

// stubHash is a hash.Hash implementation that does nothing.
type stubHash struct{}

func newStubHash() hash.Hash {
	return new(stubHash)
}

func (h *stubHash) Write(p []byte) (int, error) { return 0, nil }
func (h *stubHash) Sum(in []byte) []byte        { return in }
func (h *stubHash) Reset()                      {}
func (h *stubHash) Size() int                   { return 0 }
func (h *stubHash) BlockSize() int              { return 0 }

// Helper function for writing. Verifies that Write does not error.
func writeToHash(t *testing.T, h hash.Hash, p []byte) {
	t.Helper()

	before := make([]byte, len(p))
	copy(before, p)

	n, err := h.Write(p)
	if err != nil || n != len(p) {
		t.Errorf("Write returned error; got (%v, %v), want (nil, %v)", err, n, len(p))
	}

	if !bytes.Equal(p, before) {
		t.Errorf("Write modified input slice; got %x, want %x", p, before)
	}
}
