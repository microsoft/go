## `github.com/microsoft/go/_util`

This module is a set of utilities Microsoft uses to maintain this repository.
Run `eng/run.ps1` to list the available commands and see instructions on how to
use them.

The `_` prefix is not required for this repository, but in the microsoft/go
repository, it is required in `_util` so `cmd/internal/moddeps/moddeps_test.go`
ignores it. See
[eng/_util/README.md](https://github.com/microsoft/go/eng/_util/) for more
information. We use a `_` in microsoft/go-docker as well so the `eng/run.ps1`
script (which assumes a `_` prefix) can be reused without any modification.
