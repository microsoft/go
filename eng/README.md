# `eng`: the Microsoft infrastructure to build Go

This directory contains build infrastructure files that Microsoft uses to build
Go. This directory serves a similar purpose to https://github.com/golang/build,
which stores the build infrastructure for the upstream Go repo,
https://go.googlesource.com/go.

The directory name, "eng", is short for "engineering". We use this name because
the [dotnet/arcade](https://github.com/dotnet/arcade) auto-update process
specifically looks for `eng/Version.Details.xml` and `eng/common/` absolute
paths.

The [microsoft/go-infra](https://github.com/microsoft/go-infra) repository also
implements part of the infrastructure used to build Go, and more tools for
project maintenance. For example, it implements code flow: updating the
submodule to new Go commits.

## Building Go

In the root of the repository, run this command:

```pwsh
pwsh eng/run.ps1 build -refresh
```

* `-refresh` refreshes the Go submodule (updates it, cleans it, and applies
  patches) before the command builds the repository. Remove `-refresh` if you've
  made changes in the submodule (`go`) that you want to keep.
* Add `-test` to run tests after the build completes.
* Add `-pack` to create an archive file containing the Go build in
  `eng/artifacts/bin`. (A `.tar.gz` or `.zip` file, depending on GOOS)

Run this command for more information:

```
pwsh eng/run.ps1 build -h
```

### Building upstream Go
The standard way to build the upstream Go repository is documented at
[https://go.dev/doc/install/source](https://go.dev/doc/install/source): run
`./make.bash` in Go's `src` directory.

The `eng/run.ps1 build` script uses the same upstream scripts, but wraps them
and provides extra functionality. It automatically downloads a version of Go and
uses that to build, and also builds the race runtime once the standard build is
complete, to match the content of the official binary releases of Go.

## Patch files

The Microsoft Go repository uses patch files to apply changes to the `go`
submodule. The patch files are found in [`/patches`](/patches). The `-refresh`
argument to the `build` tool applies patches. Or, try:

```
pwsh eng/run.ps1 submodule-refresh -h
```

These patch files contain all the changes made to the upstream Go source code.
To explore them with Git, run `pwsh eng/run.ps1 submodule-refresh -commits` and
look at Git history inside the `go` submodule.
