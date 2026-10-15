# Microsoft build of Go patches

The patches in this directory are applied to the `/go` submodule before building the Microsoft build of Go.
This is done automatically by the build tools provided in `/eng`.

We use [`git-go-patch`](https://github.com/microsoft/go-infra/tree/main/cmd/git-go-patch) to maintain these patch files and the `index.json` file.

You can also use `git apply` and `git am` directly to apply these `*.patch` files to the `/go` submodule.
The `index.json` file contains metadata that helps the maintainers resolve patch conflicts, but it is not otherwise necessary.

See [the `/eng` README](../eng/README.md) for more information.
