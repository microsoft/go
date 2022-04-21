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
	"strings"

	"github.com/microsoft/go/_core/buildutil"
	gotestsumcmd "gotest.tools/gotestsum/cmd"
)

const description = `
This command is used in CI to run a build/test/pack configuration.

Example: Build and run tests using the dev scripts:

  eng/run.ps1 run-builder -builder linux-amd64-devscript

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
	var builder = flag.String("builder", "", "[Required] Specify a builder to run. Note, this may be destructive!")
	var jUnitFile = flag.String("junitfile", "", "Write a JUnit XML file to this path if this builder runs tests.")
	var help = flag.Bool("h", false, "Print this help message.")

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
		runOrPanic("eng/workaround-install-mercurial.sh")
	}

	maxTestRetries := buildutil.MaxTestRetryAttemptsOrExit()

	// Some builder configurations need extra env variables set up during the build, not just while
	// running tests:
	switch config {
	case "clang":
		env("CC", "/usr/bin/clang-3.9")
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

	runOrPanic("pwsh", "eng/run.ps1", "build")

	// After the build completes, run builder-specific commands.
	switch config {
	case "devscript":
		// "devscript" is specific to the Microsoft infrastructure. It means the builder should
		// validate the run.ps1 script with "build" tool works to build and test Go. It runs a
		// subset of the "test" builder's tests, but it uses the dev workflow.
		cmdline := []string{"pwsh", "eng/run.ps1", "build", "-skipbuild", "-test"}
		runTest(cmdline, *jUnitFile)

	default:
		// Most builder configurations use "bin/go tool dist test" directly, which is the default.

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

		err := buildutil.Retry(maxTestRetries, func() error {
			return runTest(cmdline, *jUnitFile)
		})
		// If we got an ExitError, the error message was already printed by the command. We just
		// need to exit with the same exit code.
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		if err != nil {
			// Something else happened: alert the user.
			log.Fatal(err)
		}
	}
}

// env sets an env var and logs it. Panics if it doesn't succeed.
func env(key, value string) {
	fmt.Printf("Setting env '%s' to '%s'\n", key, value)
	if err := os.Setenv(key, value); err != nil {
		panic(err)
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

// runTest runs a testing command. If given a JUnit XML file path, runs the test command inside a
// gotestsum command that converts the JSON output into JUnit XML and writes it to a file at this
// path.
func runTest(cmdline []string, jUnitFile string) error {
	if jUnitFile != "" {
		// Emit verbose JSON results in stdout for conversion.
		cmdline = append(cmdline, "-json")
	}

	if *dryRun {
		fmt.Printf("---- Dry run. Would have run test command: %v\n", cmdline)
		return nil
	}

	if jUnitFile != "" {
		// Set up gotestsum args. We rely on gotestsum to run the command, capture its output, and
		// convert it to JUnit test result XML.
		gotestsumArgs := append(
			[]string{
				"--junitfile", jUnitFile,
				"--hide-summary", "skipped,output",
				"--format", "standard-quiet",
				// When a builder runs tests, some JSON lines are mixed in with standard output
				// lines. Normally gotestsum treats this as an error, but we need to allow it.
				"--ignore-non-json-output-lines",
				// We don't use 'go test', we pass our own raw command. ("cmdline" args.)
				"--raw-command",
			},
			cmdline...,
		)

		// gotestsum embeds the current version of Go into the JUnit file. This causes some
		// problems, so use GOVERSION to override the behavior and use a simple placeholder.
		//
		// To find the Go version, gotestsum first looks up GOVERSION in env. If it doesn't exist,
		// then it looks for "go" in PATH and uses the output of "go version". If Go doesn't exist
		// in PATH, then gotestsum emits a warning.
		//
		// There are two problems. First, in CI, we don't have Go in PATH, so the warning shows up.
		// It's shown as the last line of output in CI, so it seems more important than it really
		// is. Second, even if gotestsum does find Go in PATH, it's the wrong version. We're running
		// tests using the Go we just built, which is never in PATH. Both of these problems could
		// end up being red herrings in the future, but we prevent them by setting GOVERSION.
		//
		// We could run "go version", parse the output, and use that as GOVERSION. However, this
		// doesn't seem useful, because we know that we ran tests using the Go we just built.
		env("GOVERSION", "gotestsum_go_version_placeholder")

		fmt.Printf("---- Running gotestsum command: %v\n", gotestsumArgs)

		// Use "ARG_0_PLACEHOLDER" as an arbitrary placeholder name. This is because here, we're
		// essentially directly calling gotestsum's main method. The 0th arg to a main method is
		// usually the program's path. This is used in the program's help text to give example
		// commands that the user can copy-paste no matter where the executable lives or if it's
		// been renamed. However, run-builder uses gotestsum as a library, so it's compiled into our
		// binary and there is no actual 'gotestsum' program. We could pass run-builder's path, but
		// that would be misleading if it ever shows up in gotestsum's output unexpectedly. Instead,
		// pass an obvious placeholder.
		return gotestsumcmd.Run("ARG_0_PLACEHOLDER", gotestsumArgs)
	}
	// If we don't have a jUnitFile target, run the command normally.
	return run(cmdline...)
}
