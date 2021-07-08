# Storing the `dev.boringcrypto` branch as a patch

In the upstream Go repository, `dev.boringcrypto` is a Git branch:
https://github.com/golang/go/tree/dev.boringcrypto. In this directory, the
boringcrypto branch has been turned into a patch.

Upstream branches exist like this:

* `master`
  * Periodically merged into `dev.boringcrypto`
* `releasebranch.go1.16`
  * Merged into `dev.boringcrypto.go1.16` after each release.
* `releasebranch.go1.15`
  * Merged into `dev.boringcrypto.go1.15` after each release.

What we have is a **patch-based** approach. We have a `microsoft/main` branch that
corresponds to `master` and a `microsoft/releasebranch*` for each
`releasebranch`. Each of our branches contains a patch file that generates the
corresponding `dev.boringcrypto` branch. Whenever a change gets merged into an
upstream `dev.boringcrypto` branch, our infrastructure regenerates the patch
file.

A **branch-based** approach would maintain a `microsoft/{branch}` for each of the
six branches.

The following sections describe the tradeoffs between **patch-based** and
**branch-based** approaches.

## Frequency of updates from `master`

In upstream, `master` is merged into `dev.boringcrypto` every few months:

```
$ git log golang/master..golang/dev.boringcrypto --pretty=format:'%h %ci %s' --merges
ed1f812cef 2021-05-13 12:59:22 -0400 [dev.boringcrypto] all: merge commit 9d0819b27c (CL 314609) into dev.boringcrypto
03cd666173 2021-02-24 15:49:21 +0100 [dev.boringcrypto] all: merge master (5b76343) into dev.boringcrypto
0f210b75f9 2021-02-17 16:43:48 -0500 [dev.boringcrypto] all: merge master (2f0da6d) into dev.boringcrypto
5934c434c1 2020-12-02 12:57:07 -0500 [dev.boringcrypto] all: merge master into dev.boringcrypto
dea96ada17 2020-12-01 17:16:25 -0500 [dev.boringcrypto] all: merge master into dev.boringcrypto
906d6e362b 2020-11-18 10:55:34 -0800 [dev.boringcrypto] all: merge master into dev.boringcrypto
95ceba18d3 2020-11-18 13:38:14 -0500 [dev.boringcrypto] crypto/hmac: merge up to 2a206c7 and skip test
0985c1bd2d 2020-11-17 18:32:51 -0500 [dev.boringcrypto] all: merge master into dev.boringcrypto
d85ef2b979 2020-07-09 21:23:49 -0400 [dev.boringcrypto] all: merge master into dev.boringcrypto
a91ad4250c 2020-07-09 17:52:30 -0400 [dev.boringcrypto] all: merge master into dev.boringcrypto
dd98c0ca3f 2020-05-07 23:31:52 -0400 [dev.boringcrypto] all: merge master into dev.boringcrypto
a9d2e3abf7 2020-05-07 18:24:58 -0400 [dev.boringcrypto] all: merge master into dev.boringcrypto
e067ce5225 2020-04-08 17:48:41 -0400 [dev.boringcrypto] all: merge master into dev.boringcrypto
[...]
```

If we used branches, we would base our changes on these upstream merges. This
would keep us up to date with upstream's `boringcrypto` branches without much
effort on our part. However, the branch lags behind `master` most of the time.

With patches, every build applies the crypto changes onto the current `master`.

## Merge conflicts

Every time we sync `master` -> `microsoft/main`, CI implicitly checks for merge
conflicts by applying the crypto patch. If there are any conflicts, sync is
blocked. (❗)

This is not necessarily bad. By detecting merge conflicts as soon as they arise,
we can work with upstream to resolve them while the changes are still fresh.
Maintaining crypto functionality is a major goal of this repo, so early
detection may be significantly helpful.

There are workarounds to unblock sync if the conflicts are interfering with
other work:

* Temporarily disable the crypto patch and build jobs.
* Make the CI jobs that build/test the crypto patch optional.

## Infrastructure simplicity

Keeping branches to a minimum makes it easier to maintain the Microsoft
infrastructure. Adding a `dev.boringcrypto` for `master` and each release branch
means that we need some way to copy new infra features from each
non-boringcrypto branch to its boringcrypto sibling. We couldn't use simple `git
merge`s to do this, because there may be upstream commits mixed in that
shouldn't be merged yet.

By only maintaining `microsoft/main`, `microsoft/releasebranch.go1.16`, and
`microsoft/releasebranch.go1.15`, it's reasonable to do development in `main`
and cherry-pick important changes to both release branches.

The [upstream support policy](https://golang.org/doc/devel/release#policy)
results in the number of active branches staying constant:

> Each major Go release is supported until there are two newer major releases.
> For example, Go 1.5 was supported until the Go 1.7 release, and Go 1.6 was
> supported until the Go 1.8 release.

## One commit, both flavors

By enabling or disabling the patch file, you can build both flavors using a
single commit/tag. This can make it easier to narrow down a root cause to a
build flavor difference.

## Reviewability

More difficult review is a significant drawback for patches. When a patch file
is changed, the diff of a diff is hard to interpret, and review tools don't
integrate any way to review a patch with the full context of the files that it
applies to.

This isn't just a problem with `dev.boringcrypto`, but with any change we want
to maintain in a patch file. For now, we've planned to move forward with patch
files: [microsoft/go#3: Maintainable patches/forked branches](https://github.com/microsoft/go/issues/3).

We can experiment with tooling and dev practices to mitigate the issues, but
even with great tooling, it's a burden to need to use it.

# Moving `goboringcrypto_linux_amd64.syso` out of the patch

The upstream `dev.boringcrypto` branch contains a large checked-in binary file
at `src/crypto/internal/boring/goboringcrypto_linux_amd64.syso`. If it's
included in the `.patch` file, it gets very large. This could cause Git storage
problems, because the patch file will change frequently, and Git (generally)
would save a new copy of the entire patch (including encoded `syso` data) each
time.

Instead, commit the file to the current branch directly and don't include it in
the patch file. The `syso` file doesn't change as often as the other
boringcrypto files, so this way, it's less of a repo size risk.
