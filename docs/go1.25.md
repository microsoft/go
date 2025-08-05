# Microsoft build of Go 1.25 release notes

After the release of 1.25, 1.23 is no longer supported, per the [Go release policy](https://go.dev/doc/devel/release).

## 🚀 Summary

The Microsoft build of Go 1.25 introduces two major changes:

- **System-provided cryptography is now enabled by default** via the `systemcrypto` experiment.
- **Telemetry collection is now enabled by default** to help us improve the Microsoft Go toolchain based on real-world usage.

These changes help align the Microsoft build of Go with internal security policies and ensure we’re building the right tools for our users.

---

## 🔐 System Crypto Backend Enabled by Default

Starting in Go 1.25, the Microsoft build of Go enables the `systemcrypto` experiment by default:

- **Linux:** Uses OpenSSL (requires `cgo`)
- **Windows:** Uses CNG (does *not* require `cgo`)
- **macOS:** Systemcrypto backend remains in preview

This aligns with Microsoft’s internal security and compliance policies by ensuring system-provided cryptographic libraries are used by default.

### Why this change?

Using platform cryptography helps meet Microsoft-wide security and compliance requirements. While FIPS-140 compliance is not the primary goal, systemcrypto can make FIPS workflows easier where required.

### Will this break my builds?

You may need to take action in the following scenarios:

- **Linux builds without `cgo`:** systemcrypto requires `cgo` and a working C compiler. Either enable `cgo` or opt out by setting `GOEXPERIMENT=nosystemcrypto`.
- **Distroless/minimal containers:** Base images without OpenSSL or glibc will not support systemcrypto. Either switch base images or opt out.
- **Cross-distro deployment on Linux:** `cgo` introduces a glibc dependency. Ensure compatibility between build and deployment systems or build on the oldest supported OS version.

To opt out of systemcrypto, set `GOEXPERIMENT=nosystemcrypto`.

For full documentation, see the [Microsoft build of Go FIPS guide](https://github.com/microsoft/go/blob/microsoft/release-branch.go1.25/eng/doc/fips/UserGuide.md).

## 📊 Telemetry Collection Enabled

Go 1.25 introduces opt-out telemetry collection in the Microsoft build of Go to help us:

- Prioritise features based on usage patterns  
- Identify performance bottlenecks  
- Understand real-world developer workflows  
- Make informed decisions about future improvements  

### What data is collected?

We collect anonymised usage and performance data from the Microsoft Go toolchain. This data is handled in accordance with [Microsoft’s privacy policies](https://privacy.microsoft.com/privacystatement) and applicable laws.

### 🔒 Privacy and control

- All telemetry is **anonymised**
- You have full control and can **opt out at any time**
- Telemetry is **independent of official Go telemetry**

### 🚫 How to opt out

To disable telemetry, set `MS_GOTOOLCHAIN_TELEMETRY_ENABLED=0`.
