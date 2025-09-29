//go:build !cgo

package openssl

import (
	"unsafe"
)

// goString converts a C string pointer to a Go string for nocgo mode
func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

// goBytes converts a C byte array to a Go byte slice for nocgo mode
func goBytes(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	// Copy the data to Go memory, similar to C.GoBytes
	result := make([]byte, length)
	copy(result, unsafe.Slice((*byte)(ptr), length))
	return result
}

func CheckLeaks() {
	// No-op for nocgo mode - leak checking requires CGO
}
