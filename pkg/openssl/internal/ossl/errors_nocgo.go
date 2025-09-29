//go:build !cgo

package ossl

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

const ERR_NUM_MAX = 16

// errState represents the OpenSSL error state for nocgo version
type errState struct {
	codes []uint64
	files []string
	lines []int32
}

// retrieveErrorState retrieves errors from the OpenSSL error queue
func retrieveErrorState() *errState {
	state := &errState{
		codes: make([]uint64, 0, ERR_NUM_MAX),
		files: make([]string, 0, ERR_NUM_MAX),
		lines: make([]int32, 0, ERR_NUM_MAX),
	}

	for range ERR_NUM_MAX {
		var file *byte
		var line int32

		var code uint64
		if OPENSSL_version_major_Available() && OPENSSL_version_major() >= 3 {
			// OpenSSL 3 error handling
			code = ERR_get_error_all(&file, &line, nil, nil, nil)
		} else {
			// OpenSSL 1 error handling
			code = ERR_get_error_line(&file, &line)
		}

		if code == 0 {
			break
		}

		state.codes = append(state.codes, code)
		state.lines = append(state.lines, line)

		if file != nil {
			// Convert C string to Go string
			filename := goString(file)
			state.files = append(state.files, filename)
		} else {
			state.files = append(state.files, "")
		}
	}

	return state
}

// newMkcgoErr creates a new error from OpenSSL error queue for nocgo version
// The errst parameter is ignored in nocgo mode, errors are retrieved directly from OpenSSL
func newMkcgoErr(msg string, errst interface{}) error {
	// Retrieve error state from OpenSSL error queue
	state := retrieveErrorState()

	// If no errors in queue, return simple message
	if len(state.codes) == 0 {
		return errors.New(msg + " failed")
	}

	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")

	for i, code := range state.codes {
		b.WriteByte('\n')
		var buf [256]byte
		ERR_error_string_n(code, unsafe.SliceData(buf[:]), len(buf))
		if termIdx := bytes.IndexByte(buf[:], 0); termIdx != -1 {
			b.Write(buf[:termIdx])
		} else {
			b.Write(buf[:])
		}

		if i < len(state.files) && state.files[i] != "" {
			b.WriteString("\n\t")
			b.WriteString(state.files[i])
			b.WriteByte(':')
			if i < len(state.lines) {
				b.WriteString(strconv.Itoa(int(state.lines[i])))
			}
		}
	}

	return errors.New(b.String())
}
