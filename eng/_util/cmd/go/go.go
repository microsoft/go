// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/microsoft/go-infra/executil"
)

const description = `
This command runs the given go command using _util's version of Go with the
working directory set to the root of the _util module.

All args (except '-h', used to print this help message) pass through to Go.
`

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of go:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	// Handle "-h" using built-in logic. Technically overrides go's handling,
	// but that's fine: we expect users of these tools to know what's going on.
	flag.Parse()

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
		flag.Args()...,
	))
}
