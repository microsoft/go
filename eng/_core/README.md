## `github.com/microsoft/go/_core`

This module is a set of utilities Microsoft uses to build Go in Azure DevOps and
maintain this repository. Run `eng/build.sh -h` to list available build options,
or `eng/run.sh` to list all commands in this module.

Unlike `_util`, the `_core` module should have zero external dependencies and
only requires a stage 0 Go toolset to build. The commands in this module are
used to produce the signed Microsoft binaries.

`_core` has a `_` prefix so `cmd/internal/moddeps/moddeps_test.go` ignores it.
The moddeps tests enforce stricter requirements than this module needs to
follow.
