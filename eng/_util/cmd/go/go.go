// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/microsoft/go-infra/executil"
)

// This command runs the given go command using _util's version of Go with the
// working directory set to the root of the _util module.
//
// All args pass through to Go. Unlike other commands, "-h"/"-help" are not
// handled to give a detailed description of this command. It doesn't seem worth
// the effort to handle help args in a way that doesn't introduce further edge
// cases or usability complications.

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	stage0Goroot := os.Getenv("STAGE_0_GOROOT")
	if stage0Goroot == "" {
		return fmt.Errorf("STAGE_0_GOROOT not set")
	}

	return executil.Run(executil.Dir(
		filepath.Join("eng", "_util"),
		filepath.Join(stage0Goroot, "bin", "go"),
		os.Args[1:]...,
	))
}
