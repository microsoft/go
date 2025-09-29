//go:build !cgo && unix

package ossl

import (
	"syscall"
	"unsafe"

	_ "github.com/microsoft/go/pkg/openssl/internal/fakecgo"
)

//go:linkname runtime_cgocall runtime.cgocall

//go:noescape
func runtime_cgocall(fn uintptr, arg unsafe.Pointer) int32 // from runtime/sys_libc.go

//go:linkname noescape
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

type libcCallInfo struct {
	fn     uintptr
	n      uintptr // number of parameters
	args   uintptr // parameters
	r1, r2 uintptr // return values
}

var syscallNABI0 uintptr

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	libcArgs := libcCallInfo{
		fn: fn,
		n:  uintptr(len(args)),
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	runtime_cgocall(syscallNABI0, unsafe.Pointer(&libcArgs))
	return libcArgs.r1, libcArgs.r2, 0
}

func dlsym(handle unsafe.Pointer, symbol string, optional bool) uintptr {
	r0 := Dlsym(handle, unsafe.StringData(symbol))
	if r0 == nil {
		if !optional {
			panic("cannot get required symbol " + symbol)
		}
		return 0
	}
	return uintptr(r0)
}
