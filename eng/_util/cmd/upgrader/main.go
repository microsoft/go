// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode"
)

type depsInfo struct {
	url string // Repository URL
	ref string // Reference (branch, tag, or commit)
	mod string // Module name
	wd  string // Relative working directory from repo root
}

var infos = map[string]depsInfo{
	"openssl": {
		url: "https://github.com/microsoft/go-crypto-openssl",
		mod: "github.com/microsoft/go-crypto-openssl",
		wd:  "./go/src",
		ref: "main",
	},
	"windows": {
		url: "https://github.com/microsoft/go-crypto-winnative",
		mod: "github.com/microsoft/go-crypto-winnative",
		wd:  "./go/src",
		ref: "main",
	},
	"darwin": {
		url: "https://github.com/microsoft/go-crypto-darwin",
		mod: "github.com/microsoft/go-crypto-darwin",
		wd:  "./go/src",
		ref: "main",
	},
	"telemetry": {
		url: "https://github.com/microsoft/go-infra",
		mod: "github.com/microsoft/go-infra/telemetry",
		wd:  "./go/src/cmd",
		ref: "main",
	},
	"telemetryconfig": {
		url: "https://github.com/microsoft/go-infra",
		mod: "github.com/microsoft/go-infra/telemetry/config",
		wd:  "./go/src/cmd",
		ref: "main",
	},
}

func description() string {
	deps := slices.Collect(maps.Keys(infos))
	slices.Sort(deps)
	return `
This command upgrades the dependencies listed as arguments to their latest available commit.
Known dependencies are:
` + strings.Join(deps, " ") + `

For example, to upgrade all crypto backends, run:
	go run eng/_util/cmd/upgrader/main.go openssl windows darwin

Always run this tool using "go run", do not install it, else it may not pick up the latest configurations.
`
}

func main() {
	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of upgrader:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description())
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	deps := flag.Args()
	if len(deps) == 0 {
		log.Println("No dependencies specified")
		os.Exit(1)
	}

	// Validate input dependencies
	for _, dep := range deps {
		if _, ok := infos[dep]; !ok {
			log.Printf("Unknown dependency: %s\n", dep)
			os.Exit(1)
		}
	}

	for _, dep := range deps {
		info := infos[dep]
		if err := upgradeDependency(&info); err != nil {
			log.Printf("Failed to upgrade %s: %v\n", info.mod, err)
			os.Exit(1)
		}
	}
}

func upgradeDependency(info *depsInfo) error {
	// Placeholder for actual upgrade logic
	log.Printf("Upgrading dependency: %s\n", info.mod)

	// Fetch latest commit from default branch
	out, err := exec.Command("git", "ls-remote", info.url, info.ref).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to fetch latest commit: %v, output: %s", err, out)
	}
	fields := strings.FieldsFunc(string(out), unicode.IsSpace)
	if len(fields) == 0 {
		return fmt.Errorf("failed to parse latest commit from output: %s", out)
	}
	sha := fields[0]
	log.Printf("Latest commit for %s: %s\n", info.mod, sha)

	// Update the dependency to the latest commit
	if err := runGoCmd(info.wd, "get", fmt.Sprintf("%s@%s", info.mod, sha)); err != nil {
		return fmt.Errorf("failed to update dependency: %v", err)
	}

	// Tidy-up go.mod
	if err := runGoCmd(info.wd, "mod", "tidy"); err != nil {
		return fmt.Errorf("failed to tidy go.mod: %v", err)
	}

	// Vendor dependencies
	if err := runGoCmd(info.wd, "mod", "vendor"); err != nil {
		return fmt.Errorf("failed to vendor dependencies: %v", err)
	}
	return nil
}

var goBinary = sync.OnceValue(func() string {
	//lint:ignore SA1019 we want to know the binary that built us
	//nolint:staticcheck // deprecated okay
	path := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	log.Printf("Using %s\n", path)
	return path
})

func runGoCmd(wd string, args ...string) error {
	cmd := exec.Command(goBinary(), args...)
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%q failed: %v: %s", cmd, err, out)
	}
	return nil
}
