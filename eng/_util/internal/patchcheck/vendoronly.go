// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package patchcheck

import (
	"fmt"
	"path/filepath"
	"strings"
)

// vendorPatchGlob matches the vendor patch filename.
const vendorPatchGlob = "0001-*.patch"

// vendorOnlyPaths lists paths that must appear in the vendor patch and must
// *only* appear in the vendor patch. Each entry is either an exact path or a
// prefix ending in "/" to match a directory tree.
var vendorOnlyPaths = []string{
	"src/vendor/",
	"src/go.mod",
	"src/go.sum",
	"src/cmd/vendor/",
	"src/cmd/go.mod",
	"src/cmd/go.sum",
	"src/go/build/vendor_test.go",
	"src/crypto/deps_ignore.go",
	"src/cmd/internal/telemetry/counter/deps_ignore.go",
}

// vendorSharedPaths must appear in the vendor patch, but may also appear in
// non-vendor patches.
var vendorSharedPaths = []string{
	"src/go/build/deps_test.go",
}

func appendVendorOnlyIssues(issues []*PatchIssue, patchFile string, mods []patchModification) ([]*PatchIssue, error) {
	patchName := filepath.Base(patchFile)
	isVendorPatch, err := filepath.Match(vendorPatchGlob, patchName)
	if err != nil {
		return nil, err
	}

	for _, mod := range mods {
		vo := isVendorOnlyPath(mod.path)
		vs := isVendorSharedPath(mod.path)
		if isVendorPatch && !vo && !vs {
			issues = append(issues, &PatchIssue{
				PatchFile: patchName,
				Message:   fmt.Sprintf("vendor patch must not contain changes to non-vendor file: %s", mod.path),
			})
		}
		if !isVendorPatch && vo {
			issues = append(issues, &PatchIssue{
				PatchFile: patchName,
				Message:   fmt.Sprintf("non-vendor patch must not contain changes to vendor file: %s", mod.path),
			})
		}
	}

	if isVendorPatch {
		for _, required := range append(vendorOnlyPaths, vendorSharedPaths...) {
			found := false
			for _, mod := range mods {
				if matchPathList([]string{required}, mod.path) {
					found = true
					break
				}
			}
			if !found {
				issues = append(issues, &PatchIssue{
					PatchFile: patchName,
					Message:   fmt.Sprintf("vendor patch must contain changes to: %s", required),
				})
			}
		}
	}

	return issues, nil
}

func isVendorOnlyPath(path string) bool {
	return matchPathList(vendorOnlyPaths, path)
}

func isVendorSharedPath(path string) bool {
	return matchPathList(vendorSharedPaths, path)
}

func matchPathList(list []string, path string) bool {
	for _, p := range list {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}
