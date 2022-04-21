// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildutil

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

// Retry runs f until it succeeds or the attempt limit is reached.
func Retry(attempts int, f func() error) error {
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

// MaxMakeRetryAttemptsOrExit returns max retry attempts for the Go build according to an env var.
func MaxMakeRetryAttemptsOrExit() int {
	return maxAttemptsOrExit("GO_MAKE_MAX_RETRY_ATTEMPTS")
}

// MaxTestRetryAttemptsOrExit returns the max test retry attempts according to an env var. Shared
// between the build command and run-builder command.
func MaxTestRetryAttemptsOrExit() int {
	return maxAttemptsOrExit("GO_TEST_MAX_RETRY_ATTEMPTS")
}

func maxAttemptsOrExit(varName string) int {
	attempts, err := getEnvIntOrDefault(varName, 1)
	if err != nil {
		log.Fatal(err)
	}
	if attempts <= 0 {
		log.Fatalf("Expected positive integer for environment variable %q, but found: %v\n", varName, attempts)
	}
	return attempts
}

func getEnvIntOrDefault(varName string, defaultValue int) (int, error) {
	a, err := getEnvOrDefault(varName, strconv.Itoa(defaultValue))
	if err != nil {
		return 0, err
	}
	i, err := strconv.Atoi(a)
	if err != nil {
		return 0, fmt.Errorf("env var %q is not an int: %w", varName, err)
	}
	return i, nil
}

// getEnvOrDefault find an environment variable with name varName and returns its value. If the env
// var is not set, returns defaultValue.
//
// If the env var is found and its value is empty string, returns an error. This can't happen on
// Windows because setting an env var to empty string deletes it. However, on Linux, it is possible.
// It's likely a mistake, so we let the user know what happened with an error. For example, the env
// var might be empty string because it was set by "example=$(someCommand)" and someCommand
// encountered an error and didn't send any output to stdout.
func getEnvOrDefault(varName, defaultValue string) (string, error) {
	v, ok := os.LookupEnv(varName)
	if !ok {
		return defaultValue, nil
	}
	if v == "" {
		return "", fmt.Errorf(
			"env var %q is empty, not a valid string. To use the default string %v, unset the env var",
			varName, defaultValue)
	}
	return v, nil
}
