# Migration Guide: Microsoft build of Go

This guide provides a high-level overview of migrating from Google's standard Go distribution to Microsoft's build of Go.
The Microsoft build of Go is designed to be a drop-in replacement that adds platform-native cryptography capabilities while maintaining full compatibility with standard Go applications.

## Quick Start

**For CI/build environments:** Use Microsoft's build of Go to ensure crypto policy compliance in production builds.
As of Go 1.25+, `systemcrypto` is enabled by default on Windows and Linux.

**For local development:** Official Go builds work fine for most development scenarios.
Only install Microsoft's build locally if you need to debug specific crypto backend behavior.

**For FIPS compliance:** System crypto is already enabled by default. Configure runtime FIPS mode as needed for your specific requirements.

**To opt out of system crypto:** Set `GOEXPERIMENT=nosystemcrypto` when building (not recommended for Microsoft internal use).

## What's Different?

The Microsoft build of Go includes patches that enable:
- **FIPS 140 compliance** through platform-native crypto backends
- **System crypto integration** on Linux, Windows, and macOS
- **Toolset Telemetry** enabled by default
- **GOTOOLCHAIN disabled** by default for build reproducibility
- **Undocumented API removal** for security and maintainability
- **No code changes required** - same Go APIs
- **Runtime configuration** for FIPS mode

## Migration Steps

**Basic Migration:**
1. [Download and install](../../README.md#download-and-install) Microsoft build of Go
1. Replace your existing Go installation
1. Continue developing normally - no changes needed

**Additional steps for compliance scenarios:**
- Read the [FIPS Overview](fips/README.md) for background and configuration
- Configure runtime FIPS mode as needed for your specific requirements
- Review the [FIPS User Guide](fips/UserGuide.md) for API-specific guidance
- Set up [build automation](fips/README.md#modify-the-build-command) in CI environments
- Contact the crypto board for specific guidance (Microsoft internal teams)

## Container Migration Scenarios

Containerized deployments have specific requirements for crypto backend dependencies. Choose your approach based on your current container strategy:

### Minimal/Distroless Containers
- **Current state:** Using minimal base images like `gcr.io/distroless/static`
- **Challenge:** Missing OpenSSL and SymCrypt dependencies
- **Solution:** Switch to Microsoft build of Go container images or add required packages
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

**glibc Dependency:** Cgo introduces a dependency on the build system's version of glibc.
This may make the program incompatible with a different Linux distribution if it has a lower version of glibc.

**Deployment Strategies:**
- **Recommended:** Build and deploy using the same OS distribution and version
- **Cross-distribution:** Build on the oldest possible OS version for broader compatibility
- **Advanced:** Manually target an older version of glibc during compilation

**Container Considerations:**
- Programs built with system crypto cannot run in `scratch` containers
- Minimal containers need OpenSSL and SymCrypt packages installed
- Use Microsoft build of Go container images for pre-configured environments

### Troubleshooting Common Issues

**Panic: "crypto backend not available"**
- **Cause:** Missing required crypto libraries or incompatible versions
- **Solution:** Install required crypto packages for your platform
- **Linux:** Install `openssl`, `symcrypt`, `symcrypt-openssl` packages
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
- **[Microsoft for Go Developers Blog](https://devblogs.microsoft.com/go/)** - Updates and announcements
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