// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadGenerated reads a checked-in document through an in-module symlink so the Go test cache
// tracks it. It verifies that the symlink points to expectedDocPath before reading.
//
// When core.symlinks is false (which may happen on Windows), Git checks out symlinks as plain-text
// placeholders. If the placeholder matches the expected target, ReadGenerated falls back to
// reading expectedDocPath directly. This bypasses cache tracking for edits outside the
// module. On those checkouts, run "go test -count=1" after editing the document.
//
// The cache mechanism is described in https://pkg.go.dev/cmd/go#hdr-Test_packages:
//
//	Tests that open files within the package's module or that consult [env]
//	only match future runs in which the files and [env] are unchanged.
func ReadGenerated(linkPath, expectedDocPath string) ([]byte, error) {
	info, err := os.Lstat(linkPath)
	if err != nil {
		return nil, err
	}
	linkDir, err := filepath.Abs(filepath.Dir(linkPath))
	if err != nil {
		return nil, err
	}
	expectedPath, err := filepath.Abs(expectedDocPath)
	if err != nil {
		return nil, err
	}
	target, err := filepath.Rel(linkDir, expectedPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		got, err := os.Readlink(linkPath)
		if err != nil {
			return nil, err
		}
		if filepath.ToSlash(got) != filepath.ToSlash(target) {
			return nil, fmt.Errorf("symlink %q points to %q, want %q", linkPath, got, target)
		}
		return os.ReadFile(linkPath)
	}
	contents, err := os.ReadFile(linkPath)
	if err != nil {
		return nil, err
	}
	if string(contents) != filepath.ToSlash(target) {
		return nil, fmt.Errorf("%q is not a symlink or a Git symlink placeholder for %q", linkPath, target)
	}
	return os.ReadFile(expectedDocPath)
}

// IsCopied reports whether contents start with the automatic documentation copy notice.
func IsCopied(contents []byte) bool {
	normalized := strings.ReplaceAll(string(contents), "\r\n", "\n")
	return strings.HasPrefix(normalized, "<!--\nDO NOT EDIT THIS COPY.\nLocal edits will be overwritten.")
}
