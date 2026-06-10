// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var description = `
This command regenerates pipeline yml files in eng/pipeline using the
pipelineymlgen tool.
`

// This command exists only because it's awkward to use the "eng/_util" module
// from the root of the repository with go commands alone.

func main() {
	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	cmd := exec.Command("go", "generate", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = "eng/_util/cmd/pipelineymlgen"

	fmt.Printf("Running %q in %q...\n", cmd, cmd.Dir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %q in %q: %v", cmd, cmd.Dir, err)
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %v", err)
	}

	fmt.Printf("Done. See %s\n", filepath.Join(wd, "eng", "pipeline"))
	return nil
}
