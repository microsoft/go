package openssl_test

import (
	"testing"

	"github.com/microsoft/go/pkg/openssl"
)

func TestRand(t *testing.T) {
	_, err := openssl.RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllocations(t *testing.T) {
	if Asan() {
		t.Skip("skipping allocations test with sanitizers")
	}
	n := int(testing.AllocsPerRun(10, func() {
		buf := make([]byte, 32)
		openssl.RandReader.Read(buf)
		sink ^= buf[0]
	}))
	want := 1
	if compareCurrentVersion("go1.24") >= 0 {
		// The go1.24 compiler is able to optimize the allocation away.
		// See cgo_go124.go for more information.
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}
