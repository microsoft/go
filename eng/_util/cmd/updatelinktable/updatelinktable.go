// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/microsoft/go/_core/supportdata"
)

var description = `
This command updates the table in ` + docPath + ` and data in ` + jsonPath + `.
`

var supported = []version{
	{
		Number:       "1.22",
		LatestStable: true,
		Platforms: map[string]struct{}{
			"linux-amd64":   {},
			"linux-arm64":   {},
			"linux-armv6l":  {},
			"windows-amd64": {},
			"src":           {},
			"assets":        {},
		},
	},
	{
		Number:         "1.21",
		PreviousStable: true,
		Platforms: map[string]struct{}{
			"linux-amd64":   {},
			"linux-arm64":   {},
			"linux-armv6l":  {},
			"windows-amd64": {},
			"src":           {},
			"assets":        {},
		},
	},
}

var platformPrettyNames = map[string]string{
	"src":    "Source code",
	"assets": "Metadata",
}

type version struct {
	Number         string
	LatestStable   bool
	PreviousStable bool
	Platforms      map[string]struct{}
}

var linuxFiles = []goFileType{
	{
		Kind:      supportdata.Archive,
		Name:      "Binaries (tar.gz)",
		Ext:       ".tar.gz",
		Checksum:  true,
		Signature: true,
	},
}

var windowsFiles = []goFileType{
	{
		Kind:     supportdata.Archive,
		Name:     "Binaries (zip)",
		Ext:      ".zip",
		Checksum: true,
	},
}

var sourceFiles = []goFileType{
	{
		Kind:      supportdata.Source,
		Name:      "Source (tar.gz)",
		Ext:       ".tar.gz",
		Checksum:  true,
		Signature: true,
	},
}

var assetsFiles = []goFileType{
	{
		Kind: supportdata.Manifest,
		Name: "Asset manifest (json)",
		Ext:  ".json",
	},
}

type goFileType struct {
	Kind      supportdata.ArtifactKind
	Name      string
	Ext       string
	Checksum  bool
	Signature bool
}

func (t *goFileType) ArtifactLink(version, platform, os, arch string) *supportdata.LatestLink {
	l := supportdata.LatestLink{
		Filename: filename(version, platform, t.Ext),
		OS:       os,
		Arch:     arch,
		Version:  "go" + version,
		Kind:     t.Kind,
		URL:      baseURL + filename(version, platform, t.Ext),
	}
	if t.Checksum {
		l.ChecksumURL = baseURL + filename(version, platform, t.Ext+checksumSuffix)
	}
	if t.Signature {
		l.SignatureURL = baseURL + filename(version, platform, t.Ext+signatureSuffix)
	}
	return &l
}

func filename(version, platform, ext string) string {
	return "go" + version + "." + platform + ext
}

const checksumSuffix = ".sha256"
const checksumMsg = "Checksum (SHA256)"
const signatureSuffix = ".sig"
const signatureMsg = "Signature<sup>1</sup>"

const baseURL = "https://aka.ms/golang/release/latest/"

var docPath = filepath.Join("eng", "doc", "Downloads.md")
var jsonPath = filepath.Join("eng", "doc", "release-branch-links.json")

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

	if err := write(); err != nil {
		log.Fatalln(err)
	}
}

func write() error {
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

	table, branches := data()
	content := s[:start] + "\n\n" + table + "\n\n" + s[end:]
	if err := os.WriteFile(docPath, []byte(content), 0o666); err != nil {
		return err
	}

	branchJSON, err := json.MarshalIndent(branches, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jsonPath, append(branchJSON, '\n'), 0o666)
}

func data() (string, []supportdata.Branch) {
	var b strings.Builder
	branches := make([]supportdata.Branch, 0, len(supported))

	writeURL := func(name, url string) {
		b.WriteString("- [")
		b.WriteString(name)
		b.WriteString("](")
		b.WriteString(url)
		b.WriteString(")<br/>")
	}

	b.WriteString("|   |")
	for _, v := range supported {
		b.WriteString(" ")
		b.WriteString(v.Number)
		b.WriteString(" |")
		branches = append(branches, supportdata.Branch{
			Version:        "go" + v.Number,
			Stable:         true,
			LatestStable:   v.LatestStable,
			PreviousStable: v.PreviousStable,
		})
	}
	b.WriteString("\n| --- |")
	for range supported {
		b.WriteString(" --- |")
	}
	b.WriteString("\n|")
	for _, p := range platforms() {
		os, arch, _ := strings.Cut(p, "-")
		if p == "src" || p == "assets" {
			os = ""
		}
		b.WriteString(" ")
		b.WriteString(platformPrettyName(p))
		b.WriteString(" |")
		for vi, v := range supported {
			branch := &branches[vi]
			b.WriteString(" ")
			types := fileTypes(p)
			if _, ok := v.Platforms[p]; !ok {
				types = fileTypes("")
			}
			for _, f := range types {
				artifact := f.ArtifactLink(v.Number, p, os, arch)
				writeURL(f.Name, artifact.URL)
				branch.Files = append(branch.Files, artifact)
				if artifact.ChecksumURL != "" {
					writeURL(checksumMsg, artifact.ChecksumURL)
				}
				if artifact.SignatureURL != "" {
					writeURL(signatureMsg, artifact.SignatureURL)
				}
			}
			if len(types) == 0 {
				b.WriteString("N/A")
			}
			b.WriteString(" |")
		}
		b.WriteString("\n")
	}

	return b.String(), branches
}

func platforms() []string {
	platforms := make(map[string]struct{})
	for _, v := range supported {
		for p := range v.Platforms {
			platforms[p] = struct{}{}
		}
	}
	// Sort the platforms, but keep "src" and "assets" always on top because it's very different and shouldn't be
	// mixed in with the others. (Upstream also does this at go.dev/dl.)
	keys := make([]string, 0, len(platforms))
	for k := range platforms {
		if k != "src" && k != "assets" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	keys = append([]string{"src", "assets"}, keys...)
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
	if platform == "assets" {
		return assetsFiles
	}
	return nil
}
