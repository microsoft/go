//go:build unix && !cmd_go_bootstrap && !cgo

package openssl

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

func dlopen(file string) (handle unsafe.Pointer, err error) {
	const RTLD_LAZY = 1
	var RTLD_LOCAL = 0
	if runtime.GOOS == "darwin" {
		RTLD_LOCAL = 4 // darwin uses 4 as RTLD_LOCAL
	}
	handle = ossl.Dlopen(unsafe.StringData(file+"\x00"), int32(RTLD_LAZY|RTLD_LOCAL))
	if handle == nil {
		return nil, errors.New(goString(ossl.Dlerror()))
	}
	return handle, nil
}

func dlclose(handle unsafe.Pointer) error {
	if ossl.Dlclose(handle) != 0 {
		errstr := goString(ossl.Dlerror())
		return errors.New("openssl: can't close libcrypto: " + errstr)
	}
	return nil
}
