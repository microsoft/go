// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/microsoft/go-infra/patch"
)

const description = `
This command reads patch files from the patches/ directory and writes a JSON
array to stdout suitable for use as a GitHub Actions matrix. Each entry contains
a "number" (1-based position) and "name" (filename).

Use -github-actions to write the result to $GITHUB_OUTPUT as "patches=<json>".
`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ghActions := flag.Bool("github-actions", false, "Write the result to $GITHUB_OUTPUT.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}
	flag.Parse()

	type entry struct {
		Number int    `json:"number"`
		Name   string `json:"name"`
	}
	var entries []entry

	config, err := patch.FindAncestorConfig(".")
	if err != nil {
		return err
	}

	n := 1
	if err := patch.WalkGoPatches(config, func(s string) error {
		entries = append(entries, entry{Number: n, Name: filepath.Base(s)})
		n++
		return nil
	}); err != nil {
		return fmt.Errorf("error walking patches: %v", err)
	}

	if len(entries) == 0 {
		return errors.New("no patches found")
	}

	out, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	fmt.Println(string(out))

	if *ghActions {
		ghOutputPath := os.Getenv("GITHUB_OUTPUT")
		if ghOutputPath == "" {
			return fmt.Errorf("GITHUB_OUTPUT environment variable is not set")
		}
		f, err := os.OpenFile(ghOutputPath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintf(f, "patches=%s\n", out)
		return errors.Join(writeErr, f.Close())
	}
	return nil
}
