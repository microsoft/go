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
	"strconv"

	"github.com/microsoft/go/_core/archive"
	"github.com/microsoft/go/_core/patch"
	"github.com/microsoft/go/_core/submodule"
)

const description = `
This command builds Go, optionally running tests and packing an archive file.

Use this script to build Go on your local machine in the way the Microsoft
infrastructure builds it. "eng/run.ps1 build" automatically downloads a copy of
the Go compiler (required to build Go) then starts the build. This script is
also capable of running tests and packing an archive file: see Usage, above.

To build and test Go without the Microsoft infrastructure, use the Bash scripts
in 'src' such as 'src/run.bash' instead of this script.

Example: Build Go, run tests, and produce an archive file:

  eng/run.ps1 build -test -pack
`

func main() {
	var help = flag.Bool("h", false, "Print this help message.")
	o := &options{}

	flag.BoolVar(&o.SkipBuild, "skipbuild", false, "Disable building Go.")
	flag.BoolVar(&o.Test, "test", false, "Enable running tests.")
	flag.BoolVar(&o.JSON, "json", false, "Runs tests with -json flag to emit verbose results in JSON format. For use in CI.")
	flag.BoolVar(&o.Pack, "pack", false, "Enable creating an archive file similar to the official Go binary release.")

	flag.BoolVar(
		&o.Refresh, "refresh", false,
		"Refresh Go submodule: clean untracked files, reset tracked files, and apply patches before building.\n"+
			"For more refresh options, use the top level 'submodule-refresh' command instead of 'build'.")

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
	// example, "build" could be changed to "Build" and run-builder could use it. The reason this
	// hasn't been done yet is that gotestsum can only run a command line, not a Go function.)
	if err := build(o); err != nil {
		panic(err)
	}
}

type options struct {
	SkipBuild bool
	Test      bool
	JSON      bool
	Pack      bool
	Refresh   bool
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

	// eng/run.ps1 guarantees that the current working directory is the root of the Go repo (our
	// GOROOT). Keep track of this so we can optionally pack it up later.
	rootDir, err := os.Getwd()
	if err != nil {
		return err
	}

	if o.Refresh {
		if err := submodule.Reset(rootDir); err != nil {
			return err
		}
		if err := patch.Apply(rootDir, patch.ApplyModeIndex); err != nil {
			return err
		}
	}

	// The upstream build scripts in {repo-root}/src require your working directory to be src, or
	// they instantly fail. Change the current process dir so that we can run them.
	if err := os.Chdir("go/src"); err != nil {
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
		// To avoid this behavior and use an ambiently installed version of Go from PATH, run
		// "make.bash" manually instead of using this tool.
		if stage0Goroot := os.Getenv("STAGE_0_GOROOT"); stage0Goroot != "" {
			if err := os.Setenv("GOROOT_BOOTSTRAP", stage0Goroot); err != nil {
				return err
			}
		}

		// Set GOBUILDEXIT so 'make.bat' exits with exit code upon failure. The ordinary behavior of
		// 'make.bat' is to always end with 0 exit code even if an error occurred, so 'all.bat' can
		// handle the error. See https://github.com/golang/go/issues/7806.
		if err := os.Setenv("GOBUILDEXIT", "1"); err != nil {
			return err
		}

		maxAttempts, err := getMaxMakeRetryAttempts()
		if err != nil {
			return err
		}

		buildCommandLine := append(shellPrefix, "make"+scriptExtension)

		if err := retry(maxAttempts, func() error {
			return runCommandLine(buildCommandLine...)
		}); err != nil {
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

		maxAttempts, err := getMaxTestRetryAttempts()
		if err != nil {
			return err
		}

		// "-json": Get test results as lines of JSON.
		if o.JSON {
			testCommandLine = append(testCommandLine, "-json")
		}

		testCmd := exec.Command(testCommandLine[0], testCommandLine[1:]...)
		testCmd.Stdout = os.Stdout
		// Redirect stderr to stdout. We expect some lines of stderr to always show up during the
		// test run, but "build"'s caller might not understand that.
		//
		// For example, if we're running in CI, gotestsum may be capturing our output to report in a
		// JUnit file. If gotestsum detects output in stderr, it prints it in an error message. This
		// error message stands out, and could mislead someone trying to diagnose a failed test run.
		// Redirecting all stderr output avoids this scenario. (See /eng/_core/README.md for more
		// info on why we may be wrapped by gotestsum.)
		//
		// An example of benign stderr output is when the tests check for machine capabilities. A
		// Cgo static linking test emits "/usr/bin/ld: cannot find -lc" when it checks the
		// capabilities of "ld" on the current system.
		//
		// The stderr output isn't used to determine whether the tests succeeded or not. (The
		// redirect doesn't cause an issue where tests succeed that should have failed.)
		testCmd.Stderr = os.Stdout

		if err := retry(maxAttempts, func() error { return runCmd(testCmd) }); err != nil {
			return err
		}

		if err := runCmd(testCmd); err != nil {
			return err
		}
	}

	if o.Pack {
		goRootDir := filepath.Join(rootDir, "go")
		if err := archive.CreateFromBuild(goRootDir, ""); err != nil {
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

func retry(attempts int, f func() error) error {
	var i = 0
	for ; i < attempts; i++ {
		if attempts > 1 {
			fmt.Printf("---- Running attempt %v of %v...\n", i+1, attempts)
		}
		err := f()
		if err != nil {
			if i+1 < attempts {
				fmt.Printf("---- Attempt failed with error: %v\n", err)
				continue
			}
			fmt.Printf("---- Final attempt failed.\n")
			return err
		}
		break
	}
	fmt.Printf("---- Successful on attempt %v of %v.\n", i+1, attempts)
	return nil
}

func getMaxMakeRetryAttempts() (int, error) {
	return getEnvIntOrDefault("GO_MAKE_MAX_RETRY_ATTEMPTS", 1)
}

func getMaxTestRetryAttempts() (int, error) {
	return getEnvIntOrDefault("GO_TEST_MAX_RETRY_ATTEMPTS", 1)
}

func getEnvIntOrDefault(varName string, defaultValue int) (int, error) {
	a := os.Getenv(varName)
	if a == "" {
		return defaultValue, nil
	}
	i, err := strconv.Atoi(a)
	if err != nil {
		return 0, fmt.Errorf("env var '%v' is not an int: %w", varName, err)
	}
	return i, nil
}
