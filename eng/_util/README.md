## `github.com/microsoft/go/_util`

This module is a set of utilities Microsoft uses to build Go in Azure DevOps and
maintain this repository. Run `eng/run.ps1 build -h` to list available build
options, or `eng/run.ps1` to list all commands in this module.

### Minimal dependencies
Some commands in this module use minimal external dependencies. This reduces the
dependencies used to produce the signed Microsoft binaries.

Commands that use more than the minimal external dependencies will panic upon
init if `MS_GO_UTIL_ALLOW_ONLY_MINIMAL_DEPS` is set to `1`. This makes it
possible to test our pipelines to make sure they only use the expected commands.

The minimal dependencies are themselves tested by
`TestMinimalCommandDependencies` in `testutil`. It uses `go list` to ensure that
all commands that use more than the minimal set of dependencies include the
conditional panic upon init.

### Support for gotestsum wrapping
The `run-builder` command implements a gotestsum wrapper around the `build`
command. This isn't implemented in `build` itself to keep dependencies for the
signed build low. There are some features in the build command that accommodate
gotestsum but don't make sense as standalone features a dev would use. For
example, JSON test output and stderr redirection to stdout.

The high-level execution flow looks roughly like this when running in CI:

* `eng/pipeline/jobs/run-stage.yml`  
  runs:
* `eng/run.ps1 run-builder -test -builder linux-amd64-test -junitfile [...]`  
  which runs the Go function:
* `gotestsum.Run(... eng/run.ps1 build -test -json ...)`  
  which runs and captures the output of:
* `eng/run.ps1 build -test -json`  
  which runs [`cmd/build/build.go`](cmd/build/build.go) in this module.

> [!NOTE]
> This support is not currently used in our CI because this process seems to cut off some test output:
> [microsoft/go#1114](https://github.com/microsoft/go/issues/1114).
