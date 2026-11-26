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

### Generated Markdown checks

The reproducibility tests for generated Markdown files in this repository read documents outside the `eng/_util` module through relative symlinks inside the module in `testdata` dirs so Go's test cache tracks edits to the documents outside the module.
See [`ReadGenerated` in `docutil.go`](./internal/docutil/docutil.go) for more information.
