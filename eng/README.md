# `eng`: the Microsoft infrastructure to build Go

This directory contains build infrastructure files that Microsoft uses to build
Go. This directory serves a similar purpose to https://github.com/golang/build,
which stores the build infrastructure for the upstream Go repo,
https://go.googlesource.com/go.

The directory name, "eng", is short for "engineering".

> [!NOTE]
> We use this name for historical reasons: the
> [dotnet/arcade](https://github.com/dotnet/arcade) auto-update process
> specifically looked for `eng/Version.Details.xml` and `eng/common/` absolute
> paths. This caused us to decide to put various other infrastructure in `eng`,
> too. The `eng/pipeline` directory now locks us in: we would need to
> reconfigure every pipeline and move the yml files in every active branch in
> order to move them.

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
* Add `-packbuild` to create an archive file containing the Go build in
  `eng/artifacts/bin`. (A `.tar.gz` or `.zip` file, depending on GOOS)
* Add `-packsource` to create a `.tar.gz` file containing the Go sources in
  `eng/artifacts/bin`.

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

The Microsoft Go repository uses patch files to store changes to the `go`
submodule. The patch files are found in [`/patches`](/patches).

We created [the `git-go-patch` tool][git-go-patch] to develop and maintain the
patch files. We wrote this tool specifically for the Microsoft Go project. It's
a Go program that can be invoked as `git go-patch` after it's installed. See
[the `git-go-patch` readme][git-go-patch] for more information.

We also have some utilities in this repository to apply patches without
installing `git-go-patch`:

* `pwsh eng/run.ps1 submodule-refresh` updates the submodule and applies the
  patches.
  * Pass `-commits` to apply each patch as a separate commit.
* `pwsh eng/run.ps1 build -refresh` refreshes the submodule and applies patches
  and then goes on to build Microsoft Go.

The patch files are ordinary Git patches and can also be applied manually
without any custom tooling. Git commands like [`git
am`](https://git-scm.com/docs/git-am) and [`git
apply`](https://git-scm.com/docs/git-apply) work directly. [`git
format-patch`](https://git-scm.com/docs/git-format-patch) produces the same
patch format as `git-go-patch`.

Editing the patch files by hand is not recommended. Use `git-go-patch` or manual
`git` patching commands to let Git handle the formatting and fine details.

[git-go-patch]: https://github.com/microsoft/go-infra/tree/main/cmd/git-go-patch
