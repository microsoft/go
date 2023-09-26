This directory contains sources used to create the toolset override modules.
The Microsoft Go toolset ships with a directory that contains modules that (optionally) replace the modules a `go build` command would use.

Replacing `x/crypto` with a version of `x/crypto` that uses the OpenSSL and CNG backends is the primary use case.
Some processing is needed to produce the final result that fits the current toolset.
This directory contains the starting point that we plan to share with other Go toolset forks.

This will change to point at either:
* a shared repo that contains an `x/crypto` submodule and a set of patches, or
* a new repo with pre-applied patches, not a repo that doesn't use patches at all and is maintained as a simple branch fork.
