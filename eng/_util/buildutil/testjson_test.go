// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildutil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRunTestCmdConvertsRawOutputAfterCommand(t *testing.T) {
	t.Setenv("GO_WANT_TESTJSON_HELPER_PROCESS", "good-json")

	tmpDir := t.TempDir()
	rawOut := filepath.Join(tmpDir, "raw.jsonl")
	junitOut := filepath.Join(tmpDir, "test-results.xml")
	flags := &TestJSONFlags{
		JUnitOutFile:   junitOut,
		RawTestOutFile: rawOut,
	}

	if err := flags.RunTestCmd([]string{os.Args[0], "-test.run=TestRunTestCmdHelperProcess", "--"}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(rawOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "TestDescribeConflict") {
		t.Fatalf("raw output does not contain test event:\n%s", raw)
	}

	junit, err := os.ReadFile(junitOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), `name="net/http.TestDescribeConflict"`) {
		t.Fatalf("JUnit output does not contain package-prefixed test name:\n%s", junit)
	}
}

func TestRunTestCmdPreservesRawOutputWhenJUnitConversionFails(t *testing.T) {
	t.Setenv("GO_WANT_TESTJSON_HELPER_PROCESS", "bad-json")

	tmpDir := t.TempDir()
	rawOut := filepath.Join(tmpDir, "raw.jsonl")
	junitOut := filepath.Join(tmpDir, "test-results.xml")
	flags := &TestJSONFlags{
		JUnitOutFile:   junitOut,
		RawTestOutFile: rawOut,
	}

	err := flags.RunTestCmd([]string{os.Args[0], "-test.run=TestRunTestCmdHelperProcess", "--"})
	if err == nil {
		t.Fatal("expected JUnit conversion to fail")
	}
	if !strings.Contains(err.Error(), "no run entry for TestMissing") {
		t.Fatalf("expected missing run entry error, got %v", err)
	}

	raw, err := os.ReadFile(rawOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "TestMissing") {
		t.Fatalf("raw output does not contain failing converter line:\n%s", raw)
	}
}

func TestFailedTestPattern(t *testing.T) {
	rawOut := filepath.Join(t.TempDir(), "raw.jsonl")
	err := os.WriteFile(rawOut, []byte(`not JSON
{"Action":"fail","Package":"net/http","Test":"TestRequest"}
{"Action":"fail","Package":"net/http"}
{"Action":"fail","Package":"net/http"}
{"Action":"pass","Package":"os"}
{"Action":"fail","Package":"cmd/example:variant+race"}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	pattern, err := FailedTestPattern(rawOut)
	if err != nil {
		t.Fatal(err)
	}
	if want := `^(net/http|cmd/example:variant\+race)$`; pattern != want {
		t.Fatalf("FailedTestPattern() = %q, want %q", pattern, want)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		t.Fatalf("FailedTestPattern() returned invalid regexp: %v", err)
	}
}

func TestFailedTestPatternRequiresPackageFailure(t *testing.T) {
	rawOut := filepath.Join(t.TempDir(), "raw.jsonl")
	err := os.WriteFile(rawOut, []byte(`{"Action":"fail","Package":"net/http","Test":"TestRequest"}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = FailedTestPattern(rawOut)
	if err == nil || !strings.Contains(err.Error(), "no failed tests found") {
		t.Fatalf("expected no-failed-tests error, got %v", err)
	}
}

func TestRunTestCmdHelperProcess(t *testing.T) {
	switch os.Getenv("GO_WANT_TESTJSON_HELPER_PROCESS") {
	case "good-json":
		fmt.Print(`{"Time":"2026-05-19T07:24:14Z","Action":"start","Package":"net/http"}
{"Time":"2026-05-19T07:24:14Z","Action":"run","Package":"net/http","Test":"TestDescribeConflict"}
{"Time":"2026-05-19T07:24:14Z","Action":"output","Package":"net/http","Test":"TestDescribeConflict","Output":"=== RUN   TestDescribeConflict\n"}
{"Time":"2026-05-19T07:24:14Z","Action":"pass","Package":"net/http","Test":"TestDescribeConflict","Elapsed":0}
{"Time":"2026-05-19T07:24:14Z","Action":"pass","Package":"net/http","Elapsed":0}
`)
	case "bad-json":
		fmt.Print(`{"Time":"2026-05-19T07:24:14Z","Action":"start","Package":"net/http"}
{"Time":"2026-05-19T07:24:14Z","Action":"run","Package":"net/http","Test":"TestDescribeConflict"}
{"Time":"2026-05-19T07:24:14Z","Action":"pass","Package":"net/http","Test":"TestDescribeConflict","Elapsed":0}
{"Time":"2026-05-19T07:24:14Z","Action":"pass","Package":"net/http","Test":"TestMissing","Elapsed":0}
`)
	default:
		return
	}
	os.Exit(0)
}
