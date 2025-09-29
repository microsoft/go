//go:build !cmd_go_bootstrap

package openssl

import (
	"syscall"
	"unsafe"
)

type dlopenError struct {
	file string
	err  error
}

func (e *dlopenError) Error() string {
	return "openssl: can't load " + e.file + ": " + e.err.Error()
}

func (e *dlopenError) Unwrap() error {
	return e.err
}

func dlopen(file string) (handle unsafe.Pointer, err error) {
	// As Windows generally does not ship with a system OpenSSL library, let
	// alone a FIPS 140 certified one, use the default library search order so
	// that we preferentially load the DLL bundled with the application.
	h, err := syscall.LoadLibrary(file)
	if err != nil {
		return nil, &dlopenError{file: file, err: err}
	}
	return unsafe.Pointer(h), nil
}

func dlclose(handle unsafe.Pointer) error {
	return syscall.FreeLibrary(syscall.Handle(handle))
}
