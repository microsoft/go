//go:build cgo

package openssl

/*
#include <stdlib.h> // for free()

static inline void
go_openssl_do_leak_check(void)
{
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_ADDRESS__) && __SANITIZE_ADDRESS__) ||	\
    __has_feature(address_sanitizer)
    extern void __lsan_do_leak_check(void);
    __lsan_do_leak_check();
#endif
}
*/
import "C"
import (
	"unsafe"
)

// goString converts a C string pointer to a Go string for cgo mode
func goString(ptr *byte) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

// goBytes converts a C byte array to a Go byte slice for cgo mode
func goBytes(ptr unsafe.Pointer, length int) []byte {
	return C.GoBytes(ptr, C.int(length))
}

func CheckLeaks() {
	C.go_openssl_do_leak_check()
}
