// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const description = `
This script is used in CI to run a build/test/pack configuration.

Example: Build and run tests using the dev scripts:

  go run microsoft/run-builder.go -builder linux-amd64-devscript

For a list of builders that are run in CI, see 'azure-pipelines.yml'. This
doesn't include every builder that upstream uses. It also adds some builders
that upstream doesn't have.
(See https://github.com/golang/build/blob/master/dashboard/builders.go for a
list of upstream builders.)

CAUTION: Some builders may be destructive! For example, it might set all files
in your repository to read-only.
`

var builder = flag.String("builder", "", "[Required] Specify a builder to run. Note, this may be destructive!")
var dryRun = flag.Bool("n", false, "Enable dry run: print the commands that would be run, but do not run them.")
var help = flag.Bool("h", false, "Print this help message.")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of run-builder.go:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if len(*builder) == 0 {
		fmt.Printf("No '-builder' provided; nothing to do.\n")
		return
	}

	builderParts := strings.Split(*builder, "-")
	if len(builderParts) < 3 {
		fmt.Printf("Error: builder '%s' has less than three parts. Expected '{os}-{arch}-{config}'.\n", *builder)
		os.Exit(1)
	}

	goos, goarch, config := builderParts[0], builderParts[1], strings.Join(builderParts[2:], "-")
	fmt.Printf("Found os '%s', arch '%s', config '%s'\n", goos, goarch, config)

	if *builder == "linux-amd64-longtest" {
		run("microsoft/workaround-install-mercurial.sh")
	}

	// Tests usually use the builder name to decide what to do. However, some configurations also
	// need extra env variables set up. Some of these take effect during the Go build.
	switch config {
	case "clang":
		env("CC", "/usr/bin/clang")
	case "longtest":
		env("GO_TEST_SHORT", "false")
		env("GO_TEST_TIMEOUT_SCALE", "5")
	case "nocgo":
		env("CGO_ENABLED", "0")
	case "noopt":
		env("GO_GCFLAGS", "-N -l")
	case "regabi":
		env("GOEXPERIMENT", "regabi")
	case "ssacheck":
		env("GO_GCFLAGS", "-d=ssa/check/on,dclstack")
	case "staticlockranking":
		env("GOEXPERIMENT", "staticlockranking")
	}

	run("microsoft/build.sh")

	if config == "buildandpack" {
		run("microsoft/pack.sh")
	} else if config == "devscript" {
		run("microsoft/build.sh", "--skip-build", "--test")
	} else {

		// The tests read GO_BUILDER_NAME and make decisions based on it. For some configurations,
		// we only need to set this env var.
		env("GO_BUILDER_NAME", *builder)

		// The "fake" config "test" is a sentinel value that means we should omit the config part of
		// the builder name. This lets us have a stable "{os}-{arch}-{config}" API (particularly
		// useful when dealing with AzDO YAML limitations) while still being able to test e.g. the
		// "linux-amd64" builder from upstream.
		if config == "test" {
			env("GO_BUILDER_NAME", goos+"-"+goarch)
		}

		// 'sudo': Run under root user so we have zero UID. As of writing, all upstream builders
		// using a non-WSL Linux host run tests as root. We encounter at least one issue if we run
		// as non-root on Linux in our reimplementation: if the test infra detects non-zero UID, Go
		// makes the tree read-only while initializing tests, breaking 'longtest' tests that need to
		// open go.mod files with write permissions. https://github.com/microsoft/go/issues/53
		// tracks making tests run as non-root where possible.
		//
		// '--preserve-env': Keep the testing configuration we've set up. Sudo normally reloads env.
		//
		// 'bin/go tool dist test': Use the dist test command directly, because 'src/run.bash' isn't
		// compatible with longtest. 'src/run.bash' sets 'GOPATH=/nonexist-gopath', which breaks
		// modconv tests that download modules.
		run("sudo", "--preserve-env", "bin/go", "tool", "dist", "test")
	}
}

// env sets an env var and logs it. Panics if it doesn't succeed.
func env(key, value string) {
	fmt.Printf("Setting env '%s' to '%s'\n", key, value)
	if err := os.Setenv(key, value); err != nil {
		panic(err)
	}
}

// run runs a command, sending stdout/stderr to our streams, and panics if it doesn't succeed.
func run(name string, arg ...string) {
	c := exec.Command(name, arg...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if *dryRun {
		fmt.Printf("++ Dry run. Would have run command: %v\n", c.Args)
		return
	}

	fmt.Printf("+++ Running command: %v\n", c.Args)

	if err := c.Run(); err != nil {
		panic(err)
	}
}
