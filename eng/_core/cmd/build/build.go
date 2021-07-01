// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/microsoft/go/_core/archive"
)

const description = `
This command builds Go, optionally running tests and packing an archive file.

Use this script to build Go on your local machine in the way the Microsoft
infrastructure builds it. The "eng/build.sh" or "eng/build.ps1" script
automatically downloads a copy of the Go compiler (required to build Go) then
starts the build. This script is also capable of running tests and packing an
archive file: see Usage above.

To build and test Go without the Microsoft infrastructure, use the Bash scripts
in 'src' such as 'src/run.bash' instead of this script.

Example: Build Go, run tests, and produce an archive file:

  eng/build.sh -test -pack

  eng\build.ps1 -test -pack
`

func main() {
	var help = flag.Bool("h", false, "Print this help message.")
	o := &options{}

	flag.BoolVar(&o.SkipBuild, "skipbuild", false, "Disable building Go.")
	flag.BoolVar(&o.Test, "test", false, "Enable running tests.")
	flag.BoolVar(&o.JSON, "json", false, "Runs tests with -json flag to emit verbose results in JSON format. For use in CI.")
	flag.BoolVar(&o.Pack, "pack", false, "Enable creating an archive file similar to the official Go binary release.")

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

	// If build returns an error, handle it here with panic. Having build return an error makes it
	// easier to adapt build in the future to somewhere else in the module to use it as an API. (For
	// example, run-builder could depend on this function. The reason it doesn't right now is that
	// gotestsum can only run a command line.)
	if err := build(o); err != nil {
		panic(err)
	}
}

type options struct {
	SkipBuild bool
	Test      bool
	JSON      bool
	Pack      bool
}

func build(o *options) error {

	scriptExtension := ".bash"
	executableExtension := ""
	shellPrefix := []string{"bash"}

	if runtime.GOOS == "windows" {
		scriptExtension = ".bat"
		executableExtension = ".exe"
		shellPrefix = []string{"cmd.exe", "/c"}
	}

	rootDir, err := os.Getwd()
	if err != nil {
		return err
	}

	if err := os.Chdir("src"); err != nil {
		return err
	}

	if !o.SkipBuild {
		// If we have a stage 0 copy of Go in an env variable (as set by run.ps1), use it in the
		// build command by setting GOROOT_BOOTSTRAP. The upstream build script "make.bash" uses
		// this env variable to find the copy of Go to use to build.
		//
		// Forcing the build script to use our stage 0 avoids uncertainty that could occur if we
		// allowed it to use arbitrary versions of Go from the build machine PATH.
		//
		// To avoid this behavior and use an ambiently installed verison of Go from PATH, run
		// "make.bash" manually instead of using this tool.
		if stage0Goroot := os.Getenv("STAGE_0_GOROOT"); stage0Goroot != "" {
			if err := os.Setenv("GOROOT_BOOTSTRAP", stage0Goroot); err != nil {
				return err
			}
		}

		buildCommandLine := append(shellPrefix, "make"+scriptExtension)

		if err := runCommandLine(buildCommandLine...); err != nil {
			return err
		}

		if os.Getenv("CGO_ENABLED") != "0" {
			fmt.Println("---- Building race runtime...")
			err := runCommandLine(
				filepath.Join("..", "bin", "go"+executableExtension),
				"install", "-race", "-a", "std",
			)
			if err != nil {
				return err
			}
		}
	}

	if o.Test {
		// Normally, use the dev script to build.
		testCommandLine := append(
			shellPrefix,
			[]string{
				"run" + scriptExtension,
				"--no-rebuild",
			}...,
		)

		// "src/run.bat" doesn't pass arguments through to "dist test" like "src/run.bash" does.
		// This prevents "-json" from working properly: in "src/run.bat -json", "-json" is a no-op.
		// So, use "dist test" directly, here. Some environment variables may be subtly different,
		// but it appears to work fine for dev scenarios. https://github.com/microsoft/go/issues/109
		if runtime.GOOS == "windows" {
			testCommandLine = []string{
				filepath.Join("..", "bin", "go"+executableExtension),
				"tool", "dist", "test",
			}
		}

		// "-json": Get test results as lines of JSON.
		if o.JSON {
			testCommandLine = append(testCommandLine, "-json")
		}

		testCmd := exec.Command(testCommandLine[0], testCommandLine[1:]...)
		testCmd.Stdout = os.Stdout
		// Redirect stderr to stdout to avoid an issue with how gotestsum parses our output.
		//
		// gotestsum parses our output to look for lines of JSON. If it detects stderr output,
		// gotestsum prints it as a problem even though we expect stderr output. This error line
		// could mislead someone trying to diagnose test results. To avoid the misleading line,
		// redirect stderr to stdout so gotestsum doesn't notice it.
		//
		// For example, stderr output is normal when checking for machine capabilities. A Cgo static
		// linking test emits "/usr/bin/ld: cannot find -lc" and then skips the test because that
		// indicates static linking isn't supported with the current build/platform.
		//
		// The test script returns a correct exit code, so the redirect doesn't cause an issue where
		// the tests succeed even though they should have failed.
		testCmd.Stderr = os.Stdout

		if err := runCmd(testCmd); err != nil {
			return err
		}
	}

	if o.Pack {
		if err := archive.CreateFromBuild(rootDir, ""); err != nil {
			return err
		}
	}

	fmt.Printf("---- Build command complete.\n")
	return nil
}

func runCommandLine(commandLine ...string) error {
	c := exec.Command(commandLine[0], commandLine[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return runCmd(c)
}

func runCmd(cmd *exec.Cmd) error {
	fmt.Printf("---- Running command: %v\n", cmd.Args)
	return cmd.Run()
}
