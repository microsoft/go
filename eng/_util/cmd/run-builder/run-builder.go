// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/microsoft/go/_util/buildutil"
)

const description = `
This command is used in CI to run a build/test/pack configuration.

Example: Build and run tests using the dev scripts:

  eng/run.ps1 run-builder -build -test -builder linux-amd64-devscript

For a list of builders that are run in CI, see 'azure-pipelines.yml'. This
doesn't include every builder that upstream uses. It also adds some builders
that upstream doesn't have.
(See https://github.com/golang/build/blob/master/dashboard/builders.go for a
list of upstream builders.)

CAUTION: Some builders may be destructive! For example, it might set all files
in your repository to read-only.
`

var dryRun = flag.Bool("n", false, "Enable dry run: print the commands that would be run, but do not run them.")

func main() {
	builder := flag.String("builder", "", "[Required] Specify a builder to run. Note, this may be destructive!")
	experiment := flag.String("experiment", "", "Include this string in GOEXPERIMENT.")
	build := flag.Bool("build", false, "Run the build.")
	test := flag.Bool("test", false, "Run the tests.")

	testJSONFlags := buildutil.BindTestJSONFlags()

	help := flag.Bool("h", false, "Print this help message.")

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

	// Scale this variable to increase timeout time based on scenario or builder speed.
	timeoutScale := 1

	// Some builder configurations need extra env variables set up during the build, not just while
	// running tests:
	switch config {
	case "clang":
		buildutil.SetEnv("CC", "/usr/bin/clang-3.9")
	case "longtest":
		buildutil.SetEnv("GO_TEST_SHORT", "false")
		timeoutScale *= 5
	case "nocgo":
		buildutil.SetEnv("CGO_ENABLED", "0")
	case "noopt":
		buildutil.SetEnv("GO_GCFLAGS", "-N -l")
	case "regabi":
		buildutil.AppendExperimentEnv("regabi")
	case "ssacheck":
		buildutil.SetEnv("GO_GCFLAGS", "-d=ssa/check/on")
	case "staticlockranking":
		buildutil.AppendExperimentEnv("staticlockranking")
	}

	// Some Windows builders are slower than others and require more time for the runtime dist tests
	// in "GOMAXPROCS=2 runtime -cpu=1,2,4 -quick" mode. https://github.com/microsoft/go/issues/700
	if goos == "windows" {
		timeoutScale *= 2
	}

	if timeoutScale != 1 {
		buildutil.SetEnv("GO_TEST_TIMEOUT_SCALE", strconv.Itoa(timeoutScale))
	}

	if err := buildutil.UnassignGOROOT(); err != nil {
		log.Fatal(err)
	}

	buildCmdline := []string{"pwsh", "eng/run.ps1", "build"}

	// run.ps1 compiles Go code, so we can't use the experiment yet. We must pass the experiment
	// setting to the build command as an arg, so it can set it for the actual Go toolset build.
	if *experiment != "" {
		buildCmdline = append(buildCmdline, "-experiment", *experiment)
	}

	if *build {
		runOrPanic(buildCmdline...)
	} else {
		fmt.Println("Skipping build: '-build' not passed.")
	}

	if !*test {
		fmt.Println("Skipping tests: '-test' not passed.")
		return
	}
	// After the build completes, run builder-specific commands.
	switch config {
	case "devscript":
		// "devscript" is specific to the Microsoft infrastructure. It means the builder should
		// validate the run.ps1 script with "build" tool works to build and test Go. It runs a
		// subset of the "test" builder's tests, but it uses the dev workflow.
		testCmdline := append(buildCmdline, "-skipbuild", "-test")
		testCmdline = testJSONFlags.AppendToCmdline(testCmdline)
		if err := run(testCmdline...); err != nil {
			log.Fatal(err)
		}

	default:
		// Most builder configurations use "bin/go tool dist test" directly, which is the default.

		// Set GOEXPERIMENT in the environment now that we're using the just-built version of Go.
		if *experiment != "" {
			buildutil.AppendExperimentEnv(*experiment)
		}

		// The tests read GO_BUILDER_NAME and make decisions based on it. For some configurations,
		// we only need to set this env var.
		buildutil.SetEnv("GO_BUILDER_NAME", *builder)

		// The "fake" config "test" is a sentinel value that means we should omit the config part of
		// the builder name. This lets us have a stable "{os}-{arch}-{config}" API (particularly
		// useful when dealing with AzDO YAML limitations) while still being able to test e.g. the
		// "linux-amd64" builder from upstream.
		if config == "test" {
			buildutil.SetEnv("GO_BUILDER_NAME", goos+"-"+goarch)
		}

		cmdline := []string{
			// Use the dist test command directly, because 'src/run.bash' isn't compatible with
			// longtest. 'src/run.bash' sets 'GOPATH=/nonexist-gopath', which breaks modconv tests
			// that download modules.
			"go/bin/go", "tool", "dist", "test",
		}

		if goos == "linux" {
			cmdline = append(
				[]string{
					// Run under root user so we have zero UID. As of writing, all upstream builders using a
					// non-WSL Linux host run tests as root. We encounter at least one issue if we run as
					// non-root on Linux in our reimplementation: if the test infra detects non-zero UID, Go
					// makes the tree read-only while initializing tests, breaking 'longtest' tests that
					// need to open go.mod files with write permissions.
					// https://github.com/microsoft/go/issues/53 tracks running as non-root where possible.
					"sudo",
					// Keep testing configuration we've set up. Sudo normally reloads env.
					"--preserve-env",
				},
				cmdline...,
			)
		}

		if *dryRun {
			fmt.Printf("---- Dry run. Would have run test command: %v\n", cmdline)
		} else {
			if err := testJSONFlags.RunTestCmd(cmdline); err != nil {
				// If we got an ExitError, the error message was already printed by the command. We just
				// need to exit with the same exit code.
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					os.Exit(exitErr.ExitCode())
				}
				// Something else happened: alert the user.
				log.Fatal(err)
			}
		}
	}
}

func run(cmdline ...string) error {
	c := exec.Command(cmdline[0], cmdline[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if *dryRun {
		fmt.Printf("---- Dry run. Would have run command: %v\n", c.Args)
		return nil
	}

	fmt.Printf("---- Running command: %v\n", c.Args)
	return c.Run()
}

// runOrPanic runs a command, sending stdout/stderr to our streams, and panics if it doesn't succeed.
func runOrPanic(cmdline ...string) {
	if err := run(cmdline...); err != nil {
		panic(err)
	}
}
