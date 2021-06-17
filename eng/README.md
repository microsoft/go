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

To build Go using the Microsoft scripts, run `./build.sh`, or run `eng/build.sh`
from the root of the repository.

This is similar to running `src/make.bash` from the root of the repo, the
standard way to build the upstream Go repository. However, `build.sh` will
automatically download a version of Go and use that to build, and `build.sh`
will also build the race runtime once the standard build is complete.

Run `eng/build.sh -h` for more information.

`build.sh` supports the OS/architecture `linux_amd64`.

## Change containment

Changes specific to the Microsoft build of Go are kept inside the `eng`
directory. This helps to isolate and easily contribute changes to the upstream
Go repository.

However, there are a few places outside of `eng` that are modified to fit
infrastructure requirements:

* `/*.md` - The Microsoft GitHub organization has standard repository text that
  needs to be in these files, so the upstream Go repo text is changed.
* `/.github` - Contains CI configuration. GitHub requires files to be at this
  absolute path, so the files in the upstream Go repo need to be deleted to
  configure Microsoft's CI.
* `/global.json` - This is a .NET SDK `global.json` file. It contains the
  version of the Arcade SDK that will be used for signing our outputs. Arcade
  SDK auto-update requires this file to be in this absolute location.
* `/NuGet.config` - This is a .NET NuGet sources configuration file. This is
  also required at the root of the repo by the Arcade SDK.

For a complete list of files that are modified vs. the upstream Git repository,
first make sure you have the upstream Git refs locally. One way to do this is to
set up a remote:

```sh
git remote add golang https://github.com/microsoft/go
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
