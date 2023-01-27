// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

const description = `
Cmdscan runs the command given to it as args and monitors the output for text patterns that should
be elevated to AzDO Pipeline warnings using AzDO logging commands. Timeline events can be discovered
more easily in the UI and by automated tools like runfo.

Uses the "log issue" pipeline logging command to create timeline warnings:
https://docs.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash#logissue-log-an-error-or-warning

To specify the rules to match, pass something like "GO_CMDSCAN_RULE_" to envprefix. This detects any
env variables that start with that string and interprets their values as JSON specifying a rule. The
part of the env var after the prefix is what the rule should be called in logs. If parsing is not
successful, that rule is ignored. Cmdscan writes logs about what it finds.

When using an AzDO pipeline, SHOUT_CASE is recommended so AzDO's env var naming conversion doesn't
change the result:
https://docs.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch#environment-variables

Use "--" to unambiguously separate the flag with the command to run.

The format for a rule is a JSON object with regex string "pattern" and optionally a "url" string
that contains more information about the issue. For example:

  {"pattern": "(?i)Access is denied", "url": "https://github.com/microsoft/go/issues/241"}

Example cmdscan call:

  pwsh eng/run.ps1 cmdscan -envprefix GoCmdscanRule -- pwsh eng/run.ps1 build -test
`

type rule struct {
	Pattern string `json:"pattern"`
	URL     string `json:"url"`
}

type filter struct {
	// name is a simple description of the detected error that should be uniquely searchable so
	// runfo can keep track of this issue with "contains" searches on each timeline element.
	name string
	// url is an optional URL that links to more information about this error.
	url string
	// regexp is the regex that is matched against each line of output to find an issue.
	regexp *regexp.Regexp
}

var filters []filter

func main() {
	help := flag.Bool("h", false, "Print this help message.")
	prefix := flag.String("envprefix", "", "The env var prefix to use to find scan rules.")

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

	if *prefix != "" {
		log.Printf("Searching for rules with env var prefix %v...\n", *prefix)
		for _, e := range os.Environ() {
			if envName, envValue, ok := strings.Cut(e, "="); ok {
				if before, ruleName, ok := strings.Cut(envName, *prefix); ok && before == "" && ruleName != "" {
					f, err := parseFilter(ruleName, envValue)
					if err != nil {
						log.Printf("Failed to parse rule %q: %v\n", envName, err)
						continue
					}
					log.Printf("Parsed rule %q: %q (%v)\n", envName, f.regexp.String(), f.url)
					filters = append(filters, *f)
				}
			}
		}
		log.Printf("Found %v rules defined by env vars.\n", len(filters))
	}

	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func parseFilter(name, envValue string) (*filter, error) {
	var r rule

	if err := json.Unmarshal([]byte(envValue), &r); err != nil {
		return nil, err
	}
	if r.Pattern == "" {
		return nil, errors.New("rule defines no pattern")
	}

	exp, err := regexp.Compile(r.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rule regex: %v", err)
	}

	return &filter{
		name:   name,
		url:    r.URL,
		regexp: exp,
	}, nil
}

func run() error {
	cmd := exec.Command(flag.Args()[0], flag.Args()[1:]...)
	log.Printf("Running: %v\n", cmd)

	// Wait for scans to complete before returning.
	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	outPipeR, outPipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	// Close the write side so the read side sees EOF.
	// It's important that this happens before wg.Wait.
	defer outPipeW.Close()

	errPipeR, errPipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer errPipeW.Close()

	cmd.Stdout = outPipeW
	cmd.Stderr = errPipeW

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		if err := scan(outPipeR, os.Stdout, os.Stdout); err != nil {
			log.Fatalf("Failed to scan stdout pipe: %v\n", err)
		}
		outPipeR.Close()
		wg.Done()
	}()
	go func() {
		if err := scan(errPipeR, os.Stdout, os.Stderr); err != nil {
			log.Fatalf("Failed to scan stderr pipe: %v\n", err)
		}
		errPipeR.Close()
		wg.Done()
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
	if f.url != "" {
		issueLink = " (" + f.url + ")"
	}

	return fmt.Sprintf("##vso[task.logissue type=warning]%q%v: %v\n", f.name, issueLink, line)
}
