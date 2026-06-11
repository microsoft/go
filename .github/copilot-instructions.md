# crypto-backend

Use when implementing, modifying, or adding crypto algorithms to the Microsoft build of Go crypto backend system. Covers the end-to-end workflow: editing Go source in the submodule, backend architecture patterns, and extracting changes into patches with git go-patch.

## Development workflow

See [eng/doc/DeveloperGuide.md](/eng/doc/DeveloperGuide.md) for the full development workflow, including how to set up the repository, build, test, and work with `git go-patch`.

## Architecture overview

The Microsoft build of Go replaces upstream BoringCrypto (`crypto/internal/boring`) with a pluggable backend system (`github.com/microsoft/go/cryptobackend`). The backend dispatches crypto operations to platform-native libraries:

- **Linux**: OpenSSL via `github.com/microsoft/go-crypto-openssl`
- **Windows**: CNG via `github.com/microsoft/go-crypto-winnative`
- **macOS**: CryptoKit/CommonCrypto via `github.com/microsoft/go-crypto-darwin`

The backend is gated by the `goexperiment.systemcrypto` build tag. When disabled, `nobackend.go` provides panic stubs so the code compiles but never executes.

## Build tag conventions

- All backend files use `//go:build goexperiment.systemcrypto`. The `nobackend.go` uses `//go:build !goexperiment.systemcrypto`.
- Prefer filename suffixes (`_linux.go`, `_windows.go`, `_darwin.go`) over build tag OS constraints.
  - **Do**: `foo_linux.go` with `//go:build goexperiment.systemcrypto`
  - **Don't**: `foo.go` with `//go:build goexperiment.systemcrypto && linux`
- The `boring.go` / `notboring.go` file pair in crypto packages uses `goexperiment.systemcrypto` / `!goexperiment.systemcrypto` build tags respectively.
- Legacy build tags (`goexperiment.opensslcrypto`, `goexperiment.cngcrypto`, `goexperiment.darwincrypto`) are still emitted for source compatibility but must not be used in new code.

## Import alias convention

Always import the backend package as `boring`:

```go
import (
    boring "github.com/microsoft/go/cryptobackend"
    "github.com/microsoft/go/cryptobackend/bbig"
)
```

This preserves compatibility with upstream BoringCrypto code paths and the `bcache` caching infrastructure.

## How to add a new crypto algorithm

### 1. Add backend shims (all four files)

For each platform backend file, add:
- A `Supports*()` function that delegates to the platform library
- Type aliases for key types
- Shim functions for each operation

```go
// backend_linux.go
func SupportsMLKEM768() bool { return openssl.SupportsMLKEM768() }
type DecapsulationKeyMLKEM768 = openssl.DecapsulationKeyMLKEM768
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
    return openssl.GenerateKeyMLKEM768()
}
```

For `nobackend.go`, add matching panic stubs:

```go
func SupportsMLKEM768() bool { panic("cryptobackend: not available") }
type DecapsulationKeyMLKEM768 struct{}
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
    panic("cryptobackend: not available")
}
```

**nobackend.go stub rules**:
- Functions: panic with `"cryptobackend: not available"`
- Types: empty structs (`struct{}` or `struct{ _ int }`)
- Methods on stub types: panic
- `Supports*()`: must panic (not return false) — they should never be called when `Enabled` is `false`
- Exception: `SupportsChaCha20Poly1305()` returns `false` (for FIPS-only mode checks)

If an operation is not supported on a platform (e.g., Darwin doesn't support DSA), the platform backend should also panic with `"cryptobackend: not available"` and the `Supports*` function should return `false`.

### 2. Integrate into the crypto package

Add a backend key field to the key struct. **Be conscious of allocations** — avoid unnecessary pointer indirection when the backend type can be stored by value, but note that some backend pointers' lifetimes may be tied to system-provided objects, so this must be a deliberate decision per type:

```go
// Prefer value types when the backend type allows it
type DecapsulationKey768 struct {
    key       *mlkem.DecapsulationKey768
    boringKey boring.DecapsulationKeyMLKEM768
}
```

@qmuntal on PR #2342: *"Can we keep `boring` by value instead of by reference? Same as `k`."*

### 3. Create the gate function

The gate checks all prerequisites before dispatching to the backend:

```go
// For a single capability:
func supportsBoringMLKEM768() bool {
    return boring.Enabled && rand.IsDefaultReader(rand.Reader) && boring.SupportsMLKEM768()
}

// For algorithms with parameter sets:
func useBoringMLDSA(params Parameters) (bparams boring.MLDSAParameters, ok bool) {
    if !boring.Enabled || !rand.IsDefaultReader(rand.Reader) {
        return boring.MLDSAParameters{}, false
    }
    bparams, ok = boringMLDSAParameters(params)
    if !ok || !boring.SupportsMLDSA(bparams) {
        return boring.MLDSAParameters{}, false
    }
    return bparams, true
}
```

**Always check capability**, not just `Enabled`:

```go
// CORRECT
if boring.Enabled && boring.SupportsCurve(c.Params().Name) { ... }

// WRONG — backend may not support all parameter variations
if boring.Enabled { ... }
```

### 4. Dispatch at the top of every public function

```go
func GenerateKey768() (*DecapsulationKey768, error) {
    if supportsBoringMLKEM768() {
        key, err := boring.GenerateKeyMLKEM768()
        if err != nil {
            return nil, err
        }
        return &DecapsulationKey768{boringKey: key}, nil
    }
    // ... existing Go implementation
}
```

For methods, check which key is populated:

```go
func (dk *DecapsulationKey768) Bytes() []byte {
    if dk.key == nil {
        return dk.boringKey.Bytes()
    }
    return dk.key.Bytes()
}
```

### 5. Handle unsupported operations with fallback

When an operation isn't supported by all backends (e.g., deterministic signing), reconstruct the upstream Go key from the seed:

```go
func (sk *PrivateKey) goKey() (*mldsa.PrivateKey, error) {
    if sk.boringKey.Bytes() == nil {
        return &sk.k, nil
    }
    // Cache the reconstructed key so subsequent calls reuse it.
    if sk.k != (mldsa.PrivateKey{}) {
        return &sk.k, nil
    }
    seed := sk.boringKey.Bytes()
    var err error
    switch sk.boringKey.Parameters().String() {
    case "ML-DSA-44":
        sk.k, err = mldsa.NewPrivateKey44(seed)
    // ...
    }
    if err != nil {
        return nil, err
    }
    return &sk.k, nil
}
```

**Cache the result** — reconstructing keys is expensive. Set `sk.k` on first call so subsequent calls reuse it. @qmuntal: *"Calling NewPrivate[44,65,87] is a bit slow. We could set `sk.k` the first time goKey is used so that the next call reuses the same upstream key."*

### 6. FIPS 140-only mode

When `GODEBUG=fips140=only` is set, non-FIPS-approved algorithms must return errors:

```go
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
    if fips140only.Enforced() {
        return nil, errors.New("chacha20poly1305: use of ChaCha20Poly1305 is not allowed in FIPS 140-only mode")
    }
    return openssl.NewChaCha20Poly1305(key)
}
```

### 7. Update tests

- **Allocation tests**: Adjust expected allocation counts, don't skip. @qmuntal: *"Don't skip allocation tests. It's better to adjust the allocation expectations when systemcrypto is enabled. This way we catch regressions."*
- **`go/src/go/build/deps_test.go`**: Update if adding new package dependencies.

### 8. Update documentation

- Add the new algorithm's platform support status to `eng/_util/cmd/updatecryptodocs/docs.go`, then regenerate the doc:

```bash
cd eng/_util && go run ./cmd/updatecryptodocs
```

This regenerates `eng/doc/CrossPlatformCryptography.md` from the structured data in `docs.go`. **Do not edit `CrossPlatformCryptography.md` by hand** — it is auto-generated.

@qmuntal on the CSHAKE PR: *"LGTM, I'm only missing an update to CrossPlatformCryptography.md."*

## Design principles from @qmuntal

### Push operations into backends, not the integration layer

> "As a general rule (which has exceptions), we shouldn't implement in this layer operations that upstream implements in `internal/fips140`. For example, OpenSSL supports EVP_PKEY_eq. If CNG/CryptoKit don't provide similar helpers, we can always fallback to comparing the bytes in the backend."

If the native crypto library (OpenSSL, CNG, CryptoKit) provides a function for an operation like key comparison, implement it in the backend shim rather than reimplementing it in the crypto package integration code.

### Keep original variable names

When modifying existing upstream code, preserve the original variable names. @qmuntal on PR #2149: *"Keep the original variable name, `h`."*

### Use top-level functions over methods for approval checks

Prefer `func FIPSApprovedHash(h hash.Hash) bool` over adding a method to hash types. @qmuntal: *"This might be slightly better, because then we don't add new methods to the hash objects returned by sha256.New (and friends)."*

## Which patch gets which changes

- **`0001-Vendor-external-dependencies.patch`**: `vendor/` directory, `go.mod`, `go.sum`, `modules.txt`, `deps_ignore.go` — all module/vendor changes go here exclusively
- **`0002-Add-crypto-backends.patch`**: All crypto backend integration code — backend shims, algorithm integrations, test modifications, build system changes for systemcrypto
- **Other patches**: See their commit messages. Never duplicate changes across patches.

## Vendor changes workflow

If your crypto change requires a new or updated backend module dependency:

1. Make the vendor changes (`go.mod`, `go.sum`, `vendor/`) in the submodule
2. Commit them as a separate commit
3. Squash that commit into the `0001-Vendor-external-dependencies.patch` commit during `git go-patch rebase`
4. Squash the crypto code changes into the `0002-Add-crypto-backends.patch` commit
5. Run `git go-patch extract` to regenerate both patches
