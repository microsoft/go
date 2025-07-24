// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/microsoft/go-infra/json2junit"
)

type TestJSONFlags struct {
	JUnitOutFile   string
	RawTestOutFile string
}

func BindTestJSONFlags() *TestJSONFlags {
	var f TestJSONFlags
	flag.StringVar(
		&f.JUnitOutFile, "junitout", "junit.xml",
		"Write the test output to a new file at this path as a JUnit file if running tests.")
	flag.StringVar(
		&f.RawTestOutFile, "rawtestout", "",
		"Write raw test output to a new file at this path and summarize any test JSON before it reaches stdout.")
	return &f
}

func (f *TestJSONFlags) AppendToCmdline(cmdline []string) []string {
	if f != nil {
		if f.JUnitOutFile != "" {
			cmdline = append(cmdline, "-junitout", f.JUnitOutFile)
		}
		if f.RawTestOutFile != "" {
			cmdline = append(cmdline, "-rawtestout", f.RawTestOutFile)
		}
	}
	return cmdline
}

func (f *TestJSONFlags) RunTestCmd(cmdline []string) (err error) {
	var writers []io.Writer
	var needJSON bool

	if f != nil {
		if f.JUnitOutFile != "" {
			var jf *os.File
			if jf, err = os.Create(f.JUnitOutFile); err != nil {
				return err
			}
			defer func() {
				err = errors.Join(err, jf.Close())
			}()
			writers = append(writers, json2junit.NewConverter(jf))
			needJSON = true
		}
		if f.RawTestOutFile != "" {
			var rf *os.File
			if err := os.MkdirAll(filepath.Dir(f.RawTestOutFile), 0o755); err != nil {
				return fmt.Errorf("failed to create directory for raw test output: %w", err)
			}
			if rf, err = os.Create(f.RawTestOutFile); err != nil {
				return err
			}
			defer func() {
				err = errors.Join(err, rf.Close())
			}()
			writers = append(
				writers,
				&testJSONSummaryConverter{w: os.Stdout},
				rf,
			)
			needJSON = true
		} else {
			// If we don't summarize, we need to write directly to stdout.
			writers = append(writers, os.Stdout)
		}
	}
	if needJSON {
		cmdline = append(cmdline, "-json")
	}

	return RunCmdMultiWriter(cmdline, writers...)
}

// testJSONSummaryConverter reads Go JSON test output and writes a summary that
// is sufficient for human readability in CI while filtering out excessive
// details that would otherwise result in hard-to-load CI logs.
//
// It is very similar to default "go test" output, but only good enough. It
// doesn't have the same behavior in some situations.
type testJSONSummaryConverter struct {
	b bytes.Buffer
	w io.Writer
}

func (c *testJSONSummaryConverter) Write(b []byte) (int, error) {
	c.b.Write(b)
	lines := bytes.Split(c.b.Bytes(), []byte("\n"))
	if len(lines) < 2 {
		// We don't have a complete line yet.
		return len(b), nil
	}
	completeLines := lines[:len(lines)-1]
	for _, line := range completeLines {
		var entry jsonEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// An error means it either isn't a JSON line, or it's an invalid one.
			// In both cases, simply write it for the summary.
			fmt.Fprintf(c.w, "%q %v\n", line, err)
			continue
		}
		if entry.Action != "output" || entry.Test != "" {
			// Too much info for a summary.
			continue
		}
		if entry.Output == "PASS\n" ||
			entry.Output == "FAIL\n" {
			continue
		}
		_, _ = c.w.Write([]byte(entry.Output))
	}
	// Keep the last, incomplete line in the buffer for the next call, if any.
	c.b.Reset()
	_, _ = c.b.Write(lines[len(lines)-1])
	return len(b), nil
}

// jsonEntry is the parts of a single entry in the JSON file relevant to testJSONSummaryConverter.
type jsonEntry struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
	Elapsed float64
}
