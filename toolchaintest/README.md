# Toolchain tests

This module tests Microsoft-specific Go toolchain behavior.
It's maintained outside the upstream Go patch set.
The repository's build and CI test runners run this module alongside the upstream tests.

After [building the toolchain](../eng/doc/DeveloperGuide.md#build-the-go-toolchain), run this command from the current directory:

```sh
../go/bin/go test -count=1
```

On Windows:

```pwsh
..\go\bin\go.exe test -count=1
```

By default, the CLI tests use the Go executable in the test binary's `GOROOT`.
To use a different toolchain, such as when you run the tests with a bootstrap Go installation, specify the Go executable:

```sh
go test -count=1 -go=/path/to/microsoft-go/bin/go
```

The public `go/build` API tests use the toolchain that compiled the test binary.
Run the module with the built Microsoft build of Go executable to test the API and CLI behavior of that toolchain.

The module has no external dependencies.
It tests system-crypto build tags, cross-compilation, build information, and FIPS-mode command behavior.
