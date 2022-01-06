// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package submodule

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Reset(rootDir string) error {
	goDir := filepath.Join(rootDir, "go")

	// Update the submodule commit, and intialize if it hasn't been done already.
	if err := run(rootDir, "git", "submodule", "update", "--init"); err != nil {
		return err
	}

	// Find toplevel directories for the outer repo and what we expect to be the Go submodule. If
	// the toplevel directory is the same for both, make sure not to clean! That could result in
	// unexpectedly losing work in the outer repo. This could occur if the submodule doens't get set
	// up properly.
	rootToplevel, err := getToplevel(rootDir)
	if err != nil {
		return err
	}
	goToplevel, err := getToplevel(goDir)
	if err != nil {
		return err
	}

	if rootToplevel == goToplevel {
		return fmt.Errorf("go submodule (%v) toplevel is the same as root (%v) toplevel: %v", goDir, rootDir, goToplevel)
	}

	// Reset the index and working directory. This doesn't clean up new untracked files.
	if err := run(goDir, "git", "reset", "--hard"); err != nil {
		return err
	}
	// Delete untracked files detected by Git. Deliberately leave files that are ignored in
	// '.gitignore': these files shouldn't interfere with the build process and could be used for
	// incremental builds.
	if err := run(goDir, "git", "clean", "-df"); err != nil {
		return err
	}
	return nil
}

func getToplevel(dir string) (string, error) {
	c := exec.Command("git", "rev-parse", "--show-toplevel")
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func run(dir string, args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Dir = dir
	return runCmd(c)
}

func runCmd(cmd *exec.Cmd) error {
	fmt.Printf("---- Running command: %v\n", cmd.Args)
	return cmd.Run()
}
