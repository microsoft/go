// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Cmdscan runs the command given to it in os.Args and monitors the output for text patterns that
// should be elevated to AzDO Pipeline warnings using AzDO logging commands. Timeline events can be
// discovered more easily in the UI and by automated tools like runfo.
//
// If the pattern is associated with a known issue, the warning includes a link.
//
// Uses the "log issue" pipeline logging command: https://docs.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash#logissue-log-an-error-or-warning
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
)

var filters = []filter{
	{
		"access denied",
		"https://github.com/microsoft/go/issues/241",
		regexp.MustCompile("(?i)Access is denied"),
	},
}

type filter struct {
	// name is a simple description of the detected error that should be uniquely searchable so
	// runfo can keep track of this issue with "contains" searches on each timeline element.
	name string
	// trackingIssue is an optional URL that links to more information about this error.
	trackingIssue string
	// regexp is the regex that is matched against each line of output to find an issue.
	regexp *regexp.Regexp
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	log.Printf("Detected %v scan patterns defined in eng/_core/cmd/cmdscan/cmdscan.go\n", len(filters))
	log.Printf("Running: %v\n", cmd)

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		if err := scan(outPipe, os.Stdout, os.Stdout); err != nil {
			log.Fatalf("Failed to scan stdout pipe: %v\n", err)
		}
	}()
	go func() {
		if err := scan(errPipe, os.Stdout, os.Stderr); err != nil {
			log.Fatalf("Failed to scan stderr pipe: %v\n", err)
		}
	}()

	return cmd.Wait()
}

func scan(r io.Reader, commands, echo *os.File) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		fmt.Fprintf(echo, "%v\n", s.Text())
		for _, f := range filters {
			if f.regexp.MatchString(s.Text()) {
				fmt.Fprintf(echo, "Found pattern '%v'\n", f.regexp)
				fmt.Fprintf(commands, warn(&f, s.Text()))
			}
		}
	}
	return s.Err()
}

func warn(f *filter, line string) string {
	var issueLink string
	if f.trackingIssue != "" {
		issueLink = " (" + f.trackingIssue + ")"
	}

	return fmt.Sprintf("##vso[task.logissue type=warning]%q%v: %v\n", f.name, issueLink, line)
}
