//go:build unix && !cmd_go_bootstrap && cgo

package openssl

// #cgo LDFLAGS: -ldl
// #include <stdlib.h>
// #include <dlfcn.h>
import "C"
import (
	"errors"
	"unsafe"
)

func dlopen(file string) (handle unsafe.Pointer, err error) {
	cv := C.CString(file)
	defer C.free(unsafe.Pointer(cv))
	handle = C.dlopen(cv, C.RTLD_LAZY|C.RTLD_LOCAL)
	if handle == nil {
		errstr := C.GoString(C.dlerror())
		return nil, errors.New("openssl: can't load " + file + ": " + errstr)
	}
	return handle, nil
}

func dlclose(handle unsafe.Pointer) error {
	if C.dlclose(handle) != 0 {
		errstr := C.GoString(C.dlerror())
		return errors.New("openssl: can't close libcrypto: " + errstr)
	}
	return nil
}
