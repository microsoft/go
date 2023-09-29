// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package executil contains some common wrappers for simple use of exec.Cmd.
package executil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Run sets up the command to log directly to our stdout/stderr streams, then runs it.
func Run(c *exec.Cmd) error {
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return RunQuiet(c)
}

// RunQuiet logs the command line and runs the given command, but sends the output to os.DevNull.
func RunQuiet(c *exec.Cmd) error {
	fmt.Printf("---- Running command: %v %v\n", c.Path, c.Args)
	return c.Run()
}

// CombinedOutput runs a command and returns the output string of c.CombinedOutput.
func CombinedOutput(c *exec.Cmd) (string, error) {
	fmt.Printf("---- Running command: %v %v\n", c.Path, c.Args)
	out, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// SpaceTrimmedCombinedOutput runs CombinedOutput and trims leading/trailing spaces from the result.
func SpaceTrimmedCombinedOutput(c *exec.Cmd) (string, error) {
	out, err := CombinedOutput(c)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Dir returns a command that runs in the given dir. The command can be passed to one of the other
// funcs in this package to evaluate it and optionally get the output as a string. Dir is useful to
// construct one-liner command calls, because setting the dir is commonly needed and not settable
// with exec.Command directly.
func Dir(dir, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd
}

// MakeWorkDir creates a unique path inside the given root dir to use as a workspace. The name
// starts with the local time in a sortable format to help with browsing multiple workspaces. This
// function allows a command to run multiple times in sequence without overwriting or deleting the
// old data, for diagnostic purposes. This function uses os.MkdirAll to ensure the root dir exists.
func MakeWorkDir(rootDir string) (string, error) {
	pathDate := time.Now().Format("2006-01-02_15-04-05")
	if err := os.MkdirAll(rootDir, os.ModePerm); err != nil {
		return "", err
	}
	return os.MkdirTemp(rootDir, fmt.Sprintf("%s_*", pathDate))
}
