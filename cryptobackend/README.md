# Cryptobackend and standard-library internals

This package is maintained as the standalone module `github.com/microsoft/go/cryptobackend`, but the Microsoft build of Go compiles it from the vendored copy in the Go source tree:

```text
go/src/vendor/github.com/microsoft/go/cryptobackend
```

That location matters. Packages imported by the standard library are resolved through `GOROOT/src/vendor`, so the backend becomes part of the standard-library dependency graph even though its module source lives outside `go/src` in this repository.

Normally, Go's `internal` package rule would reject imports such as `crypto/internal/fips140only` or `crypto/internal/boring/sig` from `github.com/microsoft/go/cryptobackend`, because that import path is outside the `crypto` tree. The Microsoft build carries a narrow `cmd/go` exception for the GOROOT-vendored cryptobackend package: when the importer is under `GOROOT/src/vendor/github.com/microsoft/go/cryptobackend`, imports whose paths begin with `crypto/internal` are allowed.

The same loader hook also adds the `msgostd` tool tag when cryptobackend is imported by the standard library, or when the package directory is the GOROOT-vendored copy. Files guarded by that tag, such as `backend_windows_msgostd.go`, can therefore contain the std-only glue that wires the backend into packages like `crypto/internal/fips140only`.

The exception is deliberately scoped to the GOROOT-vendored copy. Building this module directly as an ordinary external dependency should not rely on importing `crypto/internal` packages.

## Algorithm package shape

The algorithm subpackages under `cryptobackend` mirror the algorithm-oriented layout of `crypto/internal/fips140/...`. Each package owns its platform-specific bindings directly: Linux packages call `go-crypto-openssl`, Windows packages call `go-crypto-winnative`, and Darwin packages call `go-crypto-darwin`.

These packages are intended as a migration step toward making cryptobackend usable as a drop-in replacement for `crypto/internal/fips140` without changing the backend implementation model all at once.