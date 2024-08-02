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

func main() {
	var help = flag.Bool("h", false, "Print this help message.")

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

	return executil.Run(executil.Dir(
		filepath.Join("eng", "_util"),
		filepath.Join(stage0Goroot, "bin", "go"),
		"test", "./...",
	))
}
