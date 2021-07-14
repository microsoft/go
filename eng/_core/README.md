## `github.com/microsoft/go/_core`

This module is a set of utilities Microsoft uses to build Go in Azure DevOps and
maintain this repository. Run `eng/run.ps1 build -h` to list available build
options, or `eng/run.ps1` to list all commands in this module.

Unlike `_util`, the `_core` module should have zero external dependencies and
only requires a stage 0 Go toolset to build. The commands in this module are
used to produce the signed Microsoft binaries.

`_core` has a `_` prefix so `cmd/internal/moddeps/moddeps_test.go` ignores it.
The moddeps tests enforce stricter requirements than this module needs to
follow.

### Support for gotestsum wrapping
The `_util` module implements a gotestsum wrapper around `_core`'s `build`
command. This requires some features in `_core` that accomodate gotestsum but
don't make sense as standalone features a dev would use. For example, JSON test
output and stderr redirection to stdout.

The high-level execution flow looks roughly like this when running in CI:

* `eng/pipeline/jobs/run-job.yml`  
  runs:
* `eng/run.ps1 run-builder -builder linux-amd64-test -junitfile [...]`  
  which runs the Go function:
* `gotestsum.Run(... eng/run.ps1 build -test -json ...)`  
  which runs and captures the output of:
* `eng/run.ps1 build -test -json`  
  which runs [`cmd/build/build.go`](cmd/build/build.go) in this module.

