// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var description = `
This command updates the table in ` + docPath + `.
`

var supported = []version{
	{
		"1.18",
		map[string]struct{}{
			"linux-amd64":   {},
			"linux-arm64":   {},
			"linux-armv6l":  {},
			"windows-amd64": {},
			"src":           {},
		},
	},
	{
		"1.17",
		map[string]struct{}{
			"linux-amd64":   {},
			"linux-arm64":   {},
			"linux-armv6l":  {},
			"windows-amd64": {},
			"src":           {},
		},
	},
}

var platformPrettyNames = map[string]string{
	"src": "Source code",
}

type version struct {
	Number    string
	Platforms map[string]struct{}
}

var linuxFiles = []goFileType{
	{"Binaries (tar.gz)", ".tar.gz"},
	{"Checksum (SHA256)", ".tar.gz.sha256"},
	{"Signature<sup>1</sup>", ".tar.gz.sig"},
}
var windowsFiles = []goFileType{
	{"Binaries (zip)", ".zip"},
	{"Checksum (SHA256)", ".zip.sha256"},
}
var sourceFiles = []goFileType{
	{"Source (tar.gz)", ".tar.gz"},
	{"Checksum (SHA256)", ".tar.gz.sha256"},
	{"Signature<sup>1</sup>", ".tar.gz.sig"},
}

type goFileType struct {
	Name string
	Ext  string
}

var docPath = filepath.Join("eng", "doc", "Downloads.md")

const beginMark = "<!-- BEGIN TABLES -->"
const endMark = "<!-- END TABLES -->"

func main() {
	var help = flag.Bool("h", false, "Print this help message.")

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

	if err := writeTables(); err != nil {
		log.Fatalln(err)
	}
}

func writeTables() error {
	bytes, err := os.ReadFile(docPath)
	if err != nil {
		return err
	}
	s := string(bytes)

	start := strings.Index(s, beginMark)
	if start == -1 {
		return fmt.Errorf("marker %#q not found in %#q", beginMark, docPath)
	}
	start += len(beginMark)

	end := strings.LastIndex(s, endMark)
	if end == -1 || end <= start {
		return fmt.Errorf("marker %#q not found after start mark in %#q", endMark, docPath)
	}

	content := s[:start] + "\n\n" + tables() + "\n\n" + s[end:]
	return os.WriteFile(docPath, []byte(content), 0666)
}

func tables() string {
	var b strings.Builder

	b.WriteString("|   |")
	for _, v := range supported {
		b.WriteString(" ")
		b.WriteString(v.Number)
		b.WriteString(" | ")
		b.WriteString(v.Number)
		b.WriteString("-fips |")
	}
	b.WriteString("\n| --- |")
	for range supported {
		b.WriteString(" --- | --- |")
	}
	b.WriteString("\n|")
	for _, p := range platforms() {
		b.WriteString(" ")
		b.WriteString(platformPrettyName(p))
		b.WriteString(" |")
		for _, v := range supported {
			b.WriteString(" ")
			for _, fipsSuffix := range []string{"", "-fips"} {
				types := fileTypes(p)
				if _, ok := v.Platforms[p]; !ok {
					types = fileTypes("")
				}
				for _, f := range types {
					b.WriteString("- [")
					b.WriteString(f.Name)
					b.WriteString("](https://aka.ms/golang/release/latest/go")
					b.WriteString(v.Number)
					b.WriteString(fipsSuffix)
					b.WriteString(".")
					b.WriteString(p)
					b.WriteString(f.Ext)
					b.WriteString(")<br/>")
				}
				if len(types) == 0 {
					b.WriteString("N/A")
				}
				b.WriteString(" |")
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func platforms() []string {
	platforms := make(map[string]struct{})
	for _, v := range supported {
		for p := range v.Platforms {
			platforms[p] = struct{}{}
		}
	}
	// Sort the platforms, but keep "src" always on top because it's very different and shouldn't be
	// mixed in with the others. (Upstream also does this at go.dev/dl.)
	keys := make([]string, 0, len(platforms))
	for k := range platforms {
		if k != "src" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	keys = append([]string{"src"}, keys...)
	return keys
}

func platformPrettyName(p string) string {
	if pretty, ok := platformPrettyNames[p]; ok {
		return pretty
	}
	return p
}

func fileTypes(platform string) []goFileType {
	if strings.HasPrefix(platform, "linux-") {
		return linuxFiles
	}
	if strings.HasPrefix(platform, "windows-") {
		return windowsFiles
	}
	if platform == "src" {
		return sourceFiles
	}
	return nil
}
