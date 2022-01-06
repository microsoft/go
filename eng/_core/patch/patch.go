// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package patch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type ApplyMode int

const (
	// ApplyModeCommits applies patches as commits. This is useful for developing changes to the
	// patches, because the commits can be automatically extracted back into patch files.
	ApplyModeCommits ApplyMode = iota
	// ApplyModeIndex applies patches as changes to the Git index and working tree. This means
	// further changes to the Go source code will show up as unstaged changes, so if any intentional
	// changes are performed in this state, they can be differentiated from the patch changes.
	ApplyModeIndex
)

func Apply(rootDir string, mode ApplyMode) error {
	goDir := filepath.Join(rootDir, "go")
	patchDir := filepath.Join(rootDir, "patches")

	cmd := exec.Command("git")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = goDir

	switch mode {
	case ApplyModeCommits:
		cmd.Args = append(cmd.Args, "am")
	case ApplyModeIndex:
		cmd.Args = append(cmd.Args, "apply", "--index")
	default:
		return fmt.Errorf("invalid patch mode '%v'", mode)
	}

	// Trailing whitespace may already be present. Don't emit warnings for it here.
	cmd.Args = append(cmd.Args, "--whitespace=nowarn")

	// ReadDir returns alphabetical order for patches: we depend on it for the patch apply order.
	entries, err := os.ReadDir(patchDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".patch" {
			continue
		}
		cmd.Args = append(cmd.Args, filepath.Join(patchDir, entry.Name()))
	}

	if err := runCmd(cmd); err != nil {
		return err
	}
	return nil
}

func runCmd(cmd *exec.Cmd) error {
	fmt.Printf("---- Running command: %v\n", cmd.Args)
	return cmd.Run()
}
