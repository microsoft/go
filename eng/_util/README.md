## `github.com/microsoft/go/_util`

This module is a set of utilities Microsoft uses to build Go in Azure DevOps and
maintain this repository. Run `eng/run.ps1` to list the available commands and
see instructions on how to use them.

`_util` has a `_` prefix so `cmd/internal/moddeps/moddeps_test.go` ignores it.
The moddeps tests enforce stricter requirements than this module needs to
follow. Specifically, the `_util` module requires the `gotestsum` library and
doesn't vendor it. `_util` is not strictly necessary to build Go, so it's ok if
its dependencies are downloaded when needed.
