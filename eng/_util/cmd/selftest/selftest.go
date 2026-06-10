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
This command runs the _util self-tests using the stage 0 Go toolchain.
`

var count = flag.Int("count", -1, "Pass '[...] -count={count}' to test runner. Use '1' to force re-run. Does nothing if negative.")

func main() {
	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of selftest:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

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

	args := []string{"test", "./..."}
	if *count >= 0 {
		args = append(args, fmt.Sprintf("-count=%d", *count))
	}

	return executil.Run(executil.Dir(
		filepath.Join("eng", "_util"),
		filepath.Join(stage0Goroot, "bin", "go"),
		args...,
	))
}
