// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package patchcheck checks Microsoft build of Go patch files for common issues
// without needing to apply them.
package patchcheck

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/microsoft/go-infra/patch"
)

type PatchIssue struct {
	// PatchFile is the base name of the patch file.
	PatchFile string
	// Message is a description of the issue.
	Message string
}

func FindPatchIssues() ([]*PatchIssue, error) {
	patchFiles, err := wdPatchList()
	if err != nil {
		return nil, err
	}
	var issues []*PatchIssue
	for _, patchFile := range patchFiles {
		patchIssues, err := checkPatch(patchFile)
		if err != nil {
			return nil, err
		}
		issues = append(issues, patchIssues...)
	}
	return issues, nil
}

func checkPatch(patchFile string) ([]*PatchIssue, error) {
	mods, err := readPatchNumstat(patchFile)
	if err != nil {
		return nil, err
	}
	var issues []*PatchIssue
	issues, err = appendVendorOnlyIssues(issues, patchFile, mods)
	if err != nil {
		return nil, err
	}
	return issues, nil
}

type patchModification struct {
	adds, removes uint64
	path          string
}

// readPatchNumstat runs "git apply --numstat" on the given patch file with
// absolute path and returns the list of modified files with their add/remove
// line counts.
func readPatchNumstat(patchFile string) ([]patchModification, error) {
	// Git only provides numstat output if we are in the root of the repository.
	// It's unclear why it doesn't work in subdirectories, even in "patches/".
	// It may be due to security features intended to prevent paths from
	// reaching outside of the repository.
	repoRoot, err := repoRoot()
	if err != nil {
		return nil, fmt.Errorf("getting repo root: %w", err)
	}

	cmd := exec.Command("git", "apply", "--no-index", "--numstat", patchFile)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git apply --no-index --numstat %s in %s: %w\noutput:\n%s", patchFile, repoRoot, err, string(out))
	}

	var mods []patchModification
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected numstat line in %s: %q", patchFile, line)
		}
		mod := patchModification{path: fields[2]}
		// Binary files show "-" for adds/removes.
		if fields[0] != "-" {
			mod.adds, err = strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing adds in %s: %q: %w", patchFile, line, err)
			}
		}
		if fields[1] != "-" {
			mod.removes, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing removes in %s: %q: %w", patchFile, line, err)
			}
		}
		mods = append(mods, mod)
	}
	return mods, nil
}

var repoRoot = sync.OnceValues(func() (string, error) {
	rootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	root, err := rootCmd.Output()
	if err != nil {
		return "", err
	}
	repoRoot := strings.TrimSpace(string(root))
	return repoRoot, nil
})

// wdPatchList is the list of patch files relative to the working directory.
var wdPatchList = sync.OnceValues(func() ([]string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	config, err := patch.FindAncestorConfig(wd)
	if err != nil {
		return nil, err
	}
	var patches []string
	if err := patch.WalkGoPatches(config, func(s string) error {
		patches = append(patches, s)
		return nil
	}); err != nil {
		return nil, err
	}
	return patches, nil
})
