package buildutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/microsoft/go-infra/json2junit"
)

type TestJSONFlags struct {
	JUnitOutFile           string
	RawTestOutArtifactName string
}

func BindTestJSONFlags() *TestJSONFlags {
	var f TestJSONFlags
	flag.StringVar(
		&f.JUnitOutFile, "junitout", "junit.xml",
		"Write the test output to this path as a JUnit file if running tests.")
	flag.StringVar(
		&f.RawTestOutArtifactName, "rawtestoutartifact", "",
		"Upload raw test output to AzDO as an artifact with this name\n"+
			"and summarize any test JSON before it reaches stdout.")
	return &f
}

func (f *TestJSONFlags) AppendToCmdline(cmdline []string) []string {
	if f != nil {
		if f.JUnitOutFile != "" {
			cmdline = append(cmdline, "-junitout", f.JUnitOutFile)
		}
		if f.RawTestOutArtifactName != "" {
			cmdline = append(cmdline, "-rawtestoutartifact", f.RawTestOutArtifactName)
		}
	}
	return cmdline
}

func (f *TestJSONFlags) RunTestCmd(cmdline []string) error {
	var writers []io.Writer
	var extraClosers []func() error

	var needJSON bool

	if f != nil {
		if f.JUnitOutFile != "" {
			jf, err := os.Create(f.JUnitOutFile)
			if err != nil {
				return err
			}
			writers = append(writers, json2junit.NewConverter(jf))
			extraClosers = append(extraClosers, jf.Close)
			needJSON = true
		}
		if f.RawTestOutArtifactName != "" {
			tmpFile, err := os.CreateTemp("", "ms-go-raw-test-out-*.txt")
			if err != nil {
				return err
			}
			fmt.Printf("---- Created temp file for raw JSON test output: %v\n", tmpFile.Name())
			writers = append(
				writers,
				&testJSONSummaryConverter{w: os.Stdout},
				tmpFile,
			)
			extraClosers = append(extraClosers, func() error {
				err := tmpFile.Close()
				fmt.Fprintf(os.Stdout, "##vso[artifact.upload artifactname=%s]%s\n", f.RawTestOutArtifactName, tmpFile.Name())
				return err
			})
			needJSON = true
		} else {
			// If we don't summarize, we need to write directly to stdout.
			writers = append(writers, os.Stdout)
		}
	}
	if needJSON {
		cmdline = append(cmdline, "-json")
	}

	errs := []error{RunCmdMultiWriter(cmdline, writers...)}
	for _, closer := range extraClosers {
		errs = append(errs, closer())
	}
	return errors.Join(errs...)
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

// jsonEntry is the parts of a single entry in the JSON file relevant to testJSONHumanConverter.
type jsonEntry struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
	Elapsed float64
}
