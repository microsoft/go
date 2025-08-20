# Migration Guide: Microsoft build of Go

This guide provides a high-level overview of migrating from Google's standard Go distribution to Microsoft's build of Go. The Microsoft build of Go is designed to be a drop-in replacement that adds FIPS 140-2 compliance capabilities while maintaining full compatibility with standard Go applications.

## Quick Start

**For most users:** The Microsoft build of Go works exactly like standard Go - no code changes required. Simply replace your Go installation and continue developing as usual. As of Go 1.25+, `systemcrypto` is enabled by default on Windows and Linux.

**For FIPS compliance:** System crypto is already enabled by default. Configure runtime FIPS mode as needed for your specific requirements.

**To opt out of system crypto:** Set `GOEXPERIMENT=nosystemcrypto` when building (not recommended for Microsoft internal use).

## What's Different?

The Microsoft build of Go includes patches that enable:
- **FIPS 140-2 compliance** through platform-native crypto backends
- **OpenSSL integration** on Linux
- **CNG (Cryptography Next Generation)** on Windows  
- **CommonCrypto/CryptoKit** on macOS
- **No code changes required** - same Go APIs
- **Runtime configuration** for FIPS mode

## Migration Paths

Choose your path based on your knowledge level and requirements:

### 🚀 Just Getting Started

**What you need:** Basic Go knowledge, want to try Microsoft's Go build

**Next steps:**
1. [Download and install](../../README.md#download-and-install) Microsoft build of Go
1. Replace your existing Go installation
1. Continue developing normally - no changes needed
1. Your applications will use standard Go crypto (non-FIPS mode)

### 🛡️ Need FIPS Compliance

**What you need:** Understanding of FIPS requirements, need compliant applications

**Next steps:**
1. Install Microsoft build of Go
1. Read the [FIPS Overview](fips/README.md) for background and configuration
1. System crypto is enabled by default (Go 1.25+) - no build configuration needed
1. Configure runtime FIPS mode as needed
1. Review the [FIPS User Guide](fips/UserGuide.md) for API-specific guidance

### ⚙️ Advanced Configuration

**What you need:** System administration experience, specific crypto requirements

**Next steps:**
1. Review [FIPS configuration options](fips/README.md#configuration-overview)
1. Understand [platform-specific FIPS modes](fips/README.md#usage-runtime)
1. Configure [Docker environments](fips/README.md#dockerfile-base-image) if needed
1. Set up [build automation](fips/README.md#modify-the-build-command)

### 🔧 Microsoft Internal Teams

**What you need:** Working at Microsoft, following internal crypto policies

**Next steps:**
1. Use Azure Linux or Ubuntu packages (automatic compliance)
1. System crypto is enabled by default (Go 1.25+) - complies with internal crypto policies
1. Follow [internal crypto policy requirements](fips/README.md#usage-common-configurations)
1. Contact the crypto board for specific guidance

## Common Scenarios

### Scenario 1: Existing Go Application
- **Goal:** Use Microsoft's Go with minimal changes
- **Solution:** Replace Go installation, rebuild with same commands
- **Result:** Application runs identically but with Microsoft's improvements

### Scenario 2: New FIPS-Compliant Application  
- **Goal:** Build a new application that meets FIPS requirements
- **Solution:** System crypto is enabled by default - configure runtime FIPS mode as needed
- **Result:** Application uses platform crypto and enforces FIPS-compliant TLS

### Scenario 3: Containerized Application
- **Goal:** Deploy FIPS-compliant app in containers
- **Solution:** Use [Microsoft Go container images](https://github.com/microsoft/go-images)
- **Result:** Pre-configured environment with FIPS capabilities

### Scenario 4: CI/CD Pipeline
- **Goal:** Automate builds with FIPS compliance
- **Solution:** System crypto is enabled by default - configure runtime environment variables as needed
- **Result:** Consistent FIPS-compliant builds across environments

## Container Migration Scenarios

Containerized deployments have specific requirements for crypto backend dependencies. Choose your approach based on your current container strategy:

### Minimal/Distroless Containers
- **Current state:** Using minimal base images like `gcr.io/distroless/static`
- **Challenge:** Missing OpenSSL and SymCrypt dependencies
- **Solution:** Switch to Microsoft Go container images or add required packages
- **Required packages:** `openssl`, `symcrypt`, `symcrypt-openssl` (SCOSSL)

### Azure Linux 3 Containers
- **Current state:** Using Azure Linux 3 as base image
- **Requirements:** Install crypto packages for FIPS compliance
- **Packages needed:**
  ```dockerfile
  RUN tdnf install -y openssl symcrypt symcrypt-openssl
  ```
- **Minimum versions:** SymCrypt-103.6.0-1, SymCrypt-OpenSSL-1.6.1-1

### Scratch Containers
- **Current state:** Building from `scratch` for minimal size
- **Challenge:** No system libraries available
- **Limitation:** Cannot use system crypto backends (OpenSSL/CNG unavailable)
- **Options:**
  1. Switch to minimal base image with crypto libraries
  1. Use `GOEXPERIMENT=nosystemcrypto` (not FIPS-compliant)
  1. Accept larger image size with required dependencies

### Migration from Standard Go Containers
- **From:** `golang:alpine` or `golang:slim`
- **To:** `mcr.microsoft.com/oss/go/microsoft/golang` images
- **Benefits:** Pre-configured with required crypto dependencies
- **Example:**
  ```dockerfile
  # Before
  FROM golang:1.25-alpine AS builder
  
  # After  
  FROM mcr.microsoft.com/oss/go/microsoft/golang:1.25-fips-cbl-mariner AS builder
  ```

## Key Differences from Standard Go

| Aspect | Standard Go | Microsoft Build |
|--------|-------------|-----------------|
| **Crypto backends** | Go standard library only | Platform-native crypto available |
| **FIPS compliance** | Not available | Full FIPS 140-2 support |
| **Dependencies** | Self-contained | May use system crypto libraries |
| **Configuration** | Build-time only | Build-time + runtime options |
| **TLS behavior** | Standard settings | FIPS-compliant settings in FIPS mode |
| **Binary size** | Smaller | Slightly larger due to crypto backends |

## Compatibility

✅ **Fully Compatible:**
- All standard Go APIs work identically
- Existing Go code requires no changes
- Same build commands and tooling
- Compatible with all Go modules and packages

⚠️ **Runtime Differences (FIPS mode only):**
- Some crypto algorithms may be restricted
- TLS connections use FIPS-approved ciphers only
- Some legacy crypto operations may not be available

### Linux Distribution Compatibility

The Microsoft build of Go uses cgo to integrate with system crypto libraries, which introduces dependencies on the build system's glibc version. This creates important compatibility considerations:

**glibc Dependency:** Cgo introduces a dependency on the build system's version of glibc. This may make the program incompatible with a different Linux distribution if it has a lower version of glibc.

**Deployment Strategies:**
- **Recommended:** Build and deploy using the same OS distribution and version
- **Cross-distribution:** Build on the oldest possible OS version for broader compatibility
- **Advanced:** Manually target an older version of glibc during compilation

**Container Considerations:**
- Programs built with system crypto cannot run in `scratch` containers
- Minimal containers need OpenSSL and SymCrypt packages installed
- Use Microsoft Go container images for pre-configured environments

### Troubleshooting Common Issues

**Panic: "crypto backend not available"**
- **Cause:** Missing OpenSSL libraries or incompatible versions
- **Solution:** Install required packages: `openssl`, `symcrypt`, `symcrypt-openssl`
- **Azure Linux 3:** Ensure minimum versions SymCrypt-103.6.0-1, SymCrypt-OpenSSL-1.6.1-1

**Panic: "FIPS mode required but not enabled"**
- **Cause:** Application built with `requirefips` tag but system not in FIPS mode
- **Solution:** Enable system FIPS mode or remove `requirefips` build constraint

**"No such file or directory" when loading libcrypto**
- **Cause:** OpenSSL not installed or not in library search path
- **Solution:** Install OpenSSL package or set `LD_LIBRARY_PATH`
- **Override:** Use `GO_OPENSSL_VERSION_OVERRIDE` environment variable

**glibc version incompatibility**
- **Error:** "version 'GLIBC_X.XX' not found"
- **Cause:** Binary built on newer glibc trying to run on older system
- **Solution:** Rebuild on target system or older glibc version

## Support and Resources

### Documentation
- **[FIPS Overview](fips/README.md)** - Comprehensive FIPS guide
- **[FIPS User Guide](fips/UserGuide.md)** - API-specific FIPS documentation
- **[CrossPlatformCryptography.md](CrossPlatformCryptography.md)** - Platform crypto details
- **[DeveloperGuide.md](DeveloperGuide.md)** - Development workflows

### Getting Help
- **[GitHub Issues](https://github.com/microsoft/go/issues)** - Bug reports and feature requests
- **[Microsoft Go Blog](https://devblogs.microsoft.com/go/)** - Updates and announcements
- **[Support Resources](../../SUPPORT.md)** - Additional support options

### Microsoft Internal
- **[Languages at Microsoft: Go](https://eng.ms/docs/more/languages-at-microsoft/go/articles/overview)**
- **Internal mailing list** for announcements and discussion

## FAQ

**Q: Do I need to change my Go code?**  
A: No, the Microsoft build of Go is a drop-in replacement. Your existing code will work without modifications.

**Q: What if I don't need FIPS compliance?**  
A: You can use the Microsoft build of Go exactly like standard Go. FIPS features are opt-in.

**Q: Can I use this for production applications?**  
A: Yes, Microsoft uses this build internally for production workloads. It follows the same support lifecycle as upstream Go.

**Q: What about performance?**  
A: Performance is comparable to standard Go. In some cases, platform-native crypto can be faster than Go's implementation.

**Q: How do I know if my application is FIPS-compliant?**  
A: Using a FIPS-certified crypto module is just one requirement. Review the [FIPS User Guide](fips/UserGuide.md) for complete compliance guidance.

**Q: Can I opt out of the system crypto backends?**  
A: Yes, set `GOEXPERIMENT=nosystemcrypto` when building. However, this is not recommended for Microsoft internal use as it may violate internal crypto policies.

---

*This guide provides a high-level overview. For detailed implementation guidance, please refer to the linked documentation sections appropriate to your needs and experience level.*