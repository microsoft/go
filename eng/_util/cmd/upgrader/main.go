package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"unicode"
)

type depsInfo struct {
	url string // Repository URL
	mod string // Module name
	wd  string // Relative working directory from repo root
}

var infos = map[string]depsInfo{
	"openssl": {
		url: "https://github.com/golang-fips/openssl",
		mod: "github.com/golang-fips/openssl/v2",
		wd:  "./go/src",
	},
	"windows": {
		url: "https://github.com/microsoft/go-crypto-winnative",
		mod: "github.com/microsoft/go-crypto-winnative",
		wd:  "./go/src",
	},
	"darwin": {
		url: "https://github.com/microsoft/go-crypto-darwin",
		mod: "github.com/microsoft/go-crypto-darwin",
		wd:  "./go/src",
	},
	"telemetry": {
		url: "https://github.com/microsoft/go-infra",
		mod: "github.com/microsoft/go-infra/telemetry",
		wd:  "./go/src/cmd",
	},
	"telemetryconfig": {
		url: "https://github.com/microsoft/go-infra",
		mod: "github.com/microsoft/go-infra/telemetry/config",
		wd:  "./go/src/cmd",
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
	go run eng/_util/cmd/upgradedeps/main.go openssl windows darwin
`
}

func main() {
	help := flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of upgradedeps:\n")
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
	out, err := exec.Command("git", "ls-remote", info.url, "HEAD").CombinedOutput()
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
	cmd := exec.Command("go", "get", fmt.Sprintf("%s@%s", info.mod, sha))
	cmd.Dir = info.wd
	if out, err = cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to update dependency: %v, output: %s", err, out)
	}

	// Tidy-up go.mod
	cmd = exec.Command("go", "mod", "tidy")
	cmd.Dir = info.wd
	if out, err = cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to tidy go.mod: %v, output: %s", err, out)
	}

	// Vendor dependencies
	cmd = exec.Command("go", "mod", "vendor")
	cmd.Dir = info.wd
	if out, err = cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to vendor dependencies: %v, output: %s", err, out)
	}
	return nil
}
