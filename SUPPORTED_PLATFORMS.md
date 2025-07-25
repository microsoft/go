# Supported Platforms

This document outlines the platform support matrix for different versions of the Microsoft build of Go.

## Support Policy

The Microsoft build of Go follows the upstream Go [Release Policy](https://go.dev/doc/devel/release#policy). This means we support each major release (1.X) until there are two newer major releases. A new Go major version is [released every six months](https://github.com/golang/go/wiki/Go-Release-Cycle), so each Go major version is supported for about one year.

## Currently Supported Versions

As of July 2025, the following Go versions are actively supported:

- **Go 1.25** (upcoming release)
- **Go 1.24** (current stable)
- **Go 1.23** (previous stable)

After the release of Go 1.25, Go 1.23 will no longer be supported.

## Platform Support Matrix

### Go 1.25 (Upcoming)

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| Linux | amd64 | ✅ Supported | Primary platform, Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | arm64 | ✅ Supported | Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | armv6l | ✅ Supported | Modern Linux distributions |
| Windows | amd64 | ✅ Supported | Windows Server 2016+, Windows 10+ |
| macOS (Darwin) | amd64 | 🔄 Preview | macOS 11+, not for production |
| macOS (Darwin) | arm64 | 🔄 Preview | macOS 11+, not for production |

### Go 1.24 (Current Stable)

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| Linux | amd64 | ✅ Supported | Primary platform, Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | arm64 | ✅ Supported | Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | armv6l | ✅ Supported | Modern Linux distributions |
| Windows | amd64 | ✅ Supported | Windows Server 2016+, Windows 10+ |
| macOS (Darwin) | amd64 | 🔄 Preview | macOS 11+, not for production |
| macOS (Darwin) | arm64 | 🔄 Preview | macOS 11+, not for production |

### Go 1.23 (Previous Stable)

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| Linux | amd64 | ✅ Supported | Primary platform, Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | arm64 | ✅ Supported | Azure Linux 3.0+, Ubuntu 22.04+ |
| Linux | armv6l | ✅ Supported | Modern Linux distributions |
| Windows | amd64 | ✅ Supported | Windows Server 2016+, Windows 10+ |
| macOS (Darwin) | amd64 | ❌ Not Available | |
| macOS (Darwin) | arm64 | ❌ Not Available | |

## Platform-Specific Notes

### Linux
- **linux-amd64**: Fully supported and tested. This is the primary development and testing platform.
- **linux-arm64**: Fully supported for ARM64-based systems.
- **linux-armv6l**: Supported for ARM v6 systems, including Raspberry Pi devices.
- **Minimum supported distributions**: 
  - Azure Linux 3.0 (recommended)
  - Ubuntu 22.04 and later
  - Other modern Linux distributions with glibc 2.17+ or musl 1.1.16+

### Windows
- **windows-amd64**: Fully supported on Windows Server 2016 and later, Windows 10 and later.
- **Minimum supported versions**:
  - Windows 10 (any version)
  - Windows Server 2016 and later
  - Windows Server Core 2016 and later

### macOS (Darwin) - Preview Status
- **darwin-amd64** and **darwin-arm64**: Available starting with Go 1.24 in preview mode.
- **Minimum supported versions**: macOS 11 (Big Sur) and later
- ⚠️ **Not recommended for production use** - these builds are experimental.
- `systemcrypto` support is also in preview status.
- Please [open an issue](https://github.com/microsoft/go/issues/new) if you encounter problems.

## Getting Help

If you need support for an additional platform or encounter issues with a supported platform:

1. Check existing issues with the [Area-Acquisition](https://github.com/microsoft/go/labels/Area-Acquisition) label
2. [File a new issue](https://github.com/microsoft/go/issues/new/choose) if your platform or issue isn't already covered
