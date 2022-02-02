# `eng`: the Microsoft infrastructure to build Go

This directory contains build infrastructure files that Microsoft uses to build
Go. This directory serves a similar purpose to https://github.com/golang/build,
which stores the build infrastructure for the upstream Go repo,
https://go.googlesource.com/go.

The directory name, "eng", is short for "engineering". This name is required
because the [dotnet/arcade](https://github.com/dotnet/arcade) auto-update
process specifically looks for `eng/Version.Details.xml` and `eng/common/`
absolute paths.

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

## Change containment

Changes specific to the Microsoft build of Go are kept inside the `eng`
directory. This helps to isolate and easily contribute changes to the upstream
Go repository.

However, there are a few places outside of `eng` that are modified to fit
infrastructure requirements:

* `/*.md` - The Microsoft GitHub organization has standard repository text that
  needs to be in these files, so the upstream Go repo text is changed.
* `/.gitattributes` - When Arcade auto-update changes files, it uses CRLF or LF
  depending on runtime/platform. The Go repo disables autocrlf, so this behavior
  causes thrashing. To fix this, we modified the attributes file to turn
  autocrlf back on for specific auto-updated files.
* `/.github` - Contains CI configuration. GitHub requires files to be at this
  absolute path, so the files in the upstream Go repo need to be deleted to
  configure Microsoft's CI.
* `/global.json` - This is a .NET SDK `global.json` file. It contains the
  version of the Arcade SDK that will be used for signing our outputs. Arcade
  SDK auto-update requires this file to be in this absolute location.
* `/NuGet.config` - This is a .NET NuGet sources configuration file. This is
  also required at the root of the repo by the Arcade SDK.

To find TODO-style comments describing intentional changes to upstream files
that seem suitable to contribute, search the repo for:

```
MICROSOFT_UPSTREAM
```

You will also find `NO MICROSOFT_UPSTREAM` marking changes that wouldn't be
useful to contribute to upstream. Typically, changes marked this way have no
effect whatsoever outside the context of the Microsoft-specific infrastructure.

For a complete list of files that are modified vs. the upstream Git repository,
first make sure you have the upstream Git refs locally. One way to do this is to
set up a remote:

```sh
git remote add golang https://go.googlesource.com/go
git fetch golang
```

Then compare `master` (for example) against the corresponding `microsoft/main`
branch:

```sh
git checkout microsoft/main
# '...' compares against the shared base commit for both branches.
git diff --name-status golang/master...
```

The diff is also calculated and included in every auto-merge PR description. You
can use this query to find the most recent `microsoft/main` auto-merge PR:
<https://github.com/microsoft/go/pulls?q=is%3Apr+author%3Amicrosoft-golang-bot+%22Merge+upstream%22>
