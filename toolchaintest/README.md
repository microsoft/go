# Toolchain Tests

Tests for Microsoft-specific Go toolchain behavior, kept outside the upstream Go patch set. The repository's build and CI test runners run this module alongside the upstream tests.

After [building the toolchain](../eng/doc/DeveloperGuide.md#build-the-go-toolchain), run from this directory:

```sh
../go/bin/go test -count=1
```

On Windows, use `..\go\bin\go.exe`.

The CLI tests default to the Go executable in the running test binary's GOROOT. To use a different toolchain, including when running the tests with a bootstrap Go installation:

```sh
go test -count=1 -go=/path/to/microsoft-go/bin/go
```

The public `go/build` API tests use the toolchain that compiles the test binary. Run the module with the built Microsoft Go executable to test both APIs and CLI behavior with that toolchain.

The module has no external dependencies. It covers system-crypto build tags, cross-compilation, build information, and FIPS-mode command behavior.
