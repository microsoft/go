// Package ossl provides a Go interface to OpenSSL.
package ossl

//go:generate go run ../../cmd/mkcgo -out zossl.go -mode dynload -package ossl shims.h
//go:generate go run ../../cmd/mkcgo -out zossl.go -nocgo -mode dynload -package ossl shims.h
//go:generate go run ../../cmd/mkcgo -out zdl.go -nocgo -mode dynamic -noerrors -package ossl -tags unix dl.h

import "unsafe"

const _OSSL_PARAM_UNMODIFIED uint = uint(^uintptr(0))

// OSSL_PARAM is a structure to pass or request object parameters.
// https://docs.openssl.org/3.0/man3/OSSL_PARAM/.
type OSSL_PARAM struct {
	Key        *byte
	DataType   uint32
	Data       unsafe.Pointer
	DataSize   uint
	ReturnSize uint
}

func ossl_param_construct(key *byte, dataType uint32, data unsafe.Pointer, dataSize int) OSSL_PARAM {
	return OSSL_PARAM{
		Key:        key,
		DataType:   dataType,
		Data:       data,
		DataSize:   uint(dataSize),
		ReturnSize: _OSSL_PARAM_UNMODIFIED,
	}
}

func OSSL_PARAM_construct_octet_string(key *byte, data unsafe.Pointer, dataSize int) OSSL_PARAM {
	return ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, data, dataSize)
}

func OSSL_PARAM_construct_int32(key *byte, data *int32) OSSL_PARAM {
	return ossl_param_construct(key, OSSL_PARAM_INTEGER, unsafe.Pointer(data), 4)
}

func OSSL_PARAM_construct_end() OSSL_PARAM {
	return OSSL_PARAM{}
}

func OSSL_PARAM_modified(param *OSSL_PARAM) bool {
	// If ReturnSize is not set, the parameter has not been modified.
	return param != nil && param.ReturnSize != _OSSL_PARAM_UNMODIFIED
}

// goString converts a C string (byte pointer) to a Go string
func goString(p *byte) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	for *(*byte)(end) != 0 {
		end = unsafe.Add(end, 1)
	}
	return string(unsafe.Slice(p, uintptr(end)-uintptr(unsafe.Pointer(p))))
}
