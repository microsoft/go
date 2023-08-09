// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const description = `
This command creates a SHA256 checksum file for the given files, in the same
location and with the same name as each given file but with ".sha256" added to
the end. Pass files as non-flag arguments.

Generated files are compatible with "sha256sum -c".
`

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
	if flag.NArg() == 0 {
		flag.Usage()
		log.Fatal("No files specified.")
	}
	for _, m := range flag.Args() {
		if err := writeSHA256ChecksumFile(m); err != nil {
			log.Fatal(err)
		}
	}
}

func writeSHA256ChecksumFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	checksum := sha256.New()
	if _, err = io.Copy(checksum, file); err != nil {
		return err
	}
	// Write the checksum in a format that "sha256sum -c" can work with. Use the base path of the
	// tarball (not full path, not relative path) because then "sha256sum -c" automatically works
	// when the file and the checksum file are downloaded to the same directory.
	content := fmt.Sprintf("%v  %v\n", hex.EncodeToString(checksum.Sum(nil)), filepath.Base(path))
	outputPath := path + ".sha256"
	if err := os.WriteFile(outputPath, []byte(content), 0o666); err != nil {
		return err
	}
	fmt.Printf("Wrote checksum file %q with content: %v", outputPath, content)
	return nil
}
