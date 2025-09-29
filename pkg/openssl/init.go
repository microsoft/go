//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

// osslHandle is the handle to the OpenSSL shared library loaded in the [Init] function.
var osslHandle unsafe.Pointer

// opensslInit loads and initializes OpenSSL.
//
// See [Init] for details about file.
func opensslInit(file string) error {
	// Load the OpenSSL shared library using dlopen.
	handle, close, err := openLibrary(file)
	if err != nil {
		return err
	}

	ossl.MkcgoLoad_(handle)
	if vMajor == 1 {
		ossl.MkcgoLoad_legacy_1(handle)
		if vPatch == 1 {
			ossl.MkcgoLoad_111(handle)
		}
	} else {
		ossl.MkcgoLoad_111(handle)
		ossl.MkcgoLoad_3(handle)
	}

	// Initialize OpenSSL.
	ossl.OPENSSL_init()
	if _, err = ossl.OPENSSL_init_crypto(
		ossl.OPENSSL_INIT_ADD_ALL_CIPHERS|
			ossl.OPENSSL_INIT_ADD_ALL_DIGESTS|
			ossl.OPENSSL_INIT_LOAD_CONFIG|
			ossl.OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
		nil); err != nil {
		close()
		return err
	}
	osslHandle = handle
	return nil
}

// initForCheckVersion loads and initialize only the
// functions required in [CheckVersion].
// It returns a close function that must be called to release the resources.
//
// This function modifies the vMajor, vMinor, and vPatch global variables as
// well as other internal global variables that facilitate OpenSSL calls.
//
// If the function succeeds, calling the close function restores the previous
// state of the global variables. If it fails, the global variables are restored
// before returning.
func initForCheckVersion(file string) (func(), error) {
	prevMajor, prevMinor, prevPatch := vMajor, vMinor, vPatch
	restoreVersion := func() {
		vMajor, vMinor, vPatch = prevMajor, prevMinor, prevPatch
	}
	handle, close, err := openLibrary(file)
	if err != nil {
		restoreVersion()
		return nil, err
	}
	initFuncs := func() (loadX func(unsafe.Pointer), unloadX func()) {
		switch vMajor {
		case 1:
			loadX = ossl.MkcgoLoad_init_1
			unloadX = ossl.MkcgoUnload_init_1
		case 3:
			loadX = ossl.MkcgoLoad_init_3
			unloadX = ossl.MkcgoUnload_init_3
		default:
			// We shouldn't get here: openLibrary should have already returned an error.
			panic(errUnsupportedVersion())
		}
		return
	}
	loadX, unloadX := initFuncs()
	loadX(handle)
	return func() {
		restoreVersion()
		close()
		unloadX()
		if osslHandle != nil {
			// If osslHandle is not nil, it means that the library was already loaded
			// and initialized. In this case, we need to reload the functions from
			// the original handle.
			loadX, _ = initFuncs()
			loadX(osslHandle)
		}
	}, nil
}

// openLibrary loads and initialize the version of OpenSSL.
// It returns the handle to the OpenSSL shared library
// and a function that can be called to release the resources.
func openLibrary(file string) (handle unsafe.Pointer, close func(), err error) {
	vMajor, vMinor, vPatch = 0, 0, 0
	handle, err = dlopen(file)
	if err != nil {
		return nil, nil, err
	}
	// Retrieve the loaded OpenSSL version and check if it is supported.
	// Notice that major and minor could not match with the version parameter
	// in case the name of the shared library file differs from the OpenSSL
	// version it contains.
	ossl.MkcgoLoad_version(handle)
	close = func() {
		dlclose(handle)
		if osslHandle == nil {
			ossl.MkcgoUnload_version()
		} else {
			ossl.MkcgoLoad_version(osslHandle)
		}
	}
	defer func() {
		if err != nil {
			close()
		}
	}()

	if ossl.OPENSSL_version_major_Available() &&
		ossl.OPENSSL_version_minor_Available() &&
		ossl.OPENSSL_version_patch_Available() {
		// Likely OpenSSL 3 or later.
		vMajor = uint(ossl.OPENSSL_version_major())
		vMinor = uint(ossl.OPENSSL_version_minor())
		vPatch = uint(ossl.OPENSSL_version_patch())
	} else if ossl.OpenSSL_version_num_Available() {
		// Likely OpenSSL 1.
		ver := ossl.OpenSSL_version_num()
		vMajor = uint(ver >> 28)
		vMinor = uint(ver >> 20 & 0xFF)
		vPatch = uint(ver >> 12 & 0xFF)
	} else {
		return handle, nil, errors.New("openssl: version not available")
	}
	var supported bool
	if vMajor == 1 {
		supported = vMinor == 1
	} else if vMajor == 3 {
		// OpenSSL guarantees API and ABI compatibility within the same major version since OpenSSL 3.
		supported = true
	}
	if !supported {
		return handle, nil, errUnsupportedVersion()
	}
	return handle, close, nil
}
