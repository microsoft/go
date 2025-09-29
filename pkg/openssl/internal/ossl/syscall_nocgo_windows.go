//go:build !cgo && windows

package ossl

import (
	"syscall"
	"unsafe"
)

var modkernel32 = syscall.NewLazyDLL("kernel32.dll")
var procGetProcAddress = modkernel32.NewProc("GetProcAddress")

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	r1, r2, err = syscall.SyscallN(fn, args...)
	return
}

func dlsym(handle unsafe.Pointer, symbol string, optional bool) uintptr {
	r0, _, err := syscall.SyscallN(procGetProcAddress.Addr(), uintptr(handle), uintptr(unsafe.Pointer(unsafe.StringData(symbol))))
	if err != 0 {
		if !optional {
			panic("cannot get required symbol " + symbol + ": " + err.Error())
		}
		return 0
	}
	return r0
}
