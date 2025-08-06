# Supported Platforms

This document outlines the platform support matrix for different versions of the Microsoft build of Go.

"Support" in this context means that Microsoft actively tests these platforms and will accept bug reports for them. Platforms outside this scope are provided support on a best-effort basis with no guarantees.

## Platform Support Matrix

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| Linux | amd64 | ✅ Supported | Azure Linux 3.0+, CBL-Mariner 2.0, Ubuntu 22.04+ |
| Linux | arm64 | ✅ Supported | Azure Linux 3.0+, CBL-Mariner 2.0, Ubuntu 22.04+ |
| Linux | armv6l | ✅ Supported | Modern Linux distributions |
| Windows | amd64 | ✅ Supported | Windows Server 2016+, Windows 10+ |
| Windows | arm64 | ✅ Supported | Windows Server 2016+, Windows 10+ |
| macOS (Darwin) | amd64 | 🔄 Preview | macOS 11+, not for production |
| macOS (Darwin) | arm64 | 🔄 Preview | macOS 11+, not for production |

## Platform Support History

### Go 1.24
- Added macOS (Darwin) amd64 and arm64 support in preview mode

### Go 1.23
- macOS (Darwin) platforms not available

## Platform-Specific Notes

### Linux
- **linux-amd64**: Fully supported and tested. This is the primary development and testing platform.
- **linux-arm64**: Fully supported for ARM64-based systems.
- **linux-armv6l**: Supported for ARM v6 systems, including Raspberry Pi devices.
- **Minimum supported distributions**: 
  - Azure Linux 3.0 (recommended)
  - Ubuntu 22.04 and later
  - CBL-Mariner 2.0
- **OpenSSL Requirements**:
  - OpenSSL 1.1.1 (supported)
  - OpenSSL 3.x (supported)
    - Built-in providers are supported
    - SymCrypt provider v1.6.0 or higher is supported

### Windows
- **windows-amd64**: Fully supported on Windows Server 2016 and later, Windows 10 and later.
- **Minimum supported versions**:
  - Windows 10 (any version)
  - Windows Server 2016 and later
  - Windows Server Core 2016 and later

### macOS (Darwin) - Preview Status
- **darwin-amd64** and **darwin-arm64**: Available in preview mode.
- **Minimum supported versions**: macOS 11 (Big Sur) and later
- ⚠️ **Not recommended for production use** - these builds are experimental.
- `systemcrypto` support is also in preview status.
- Please [open an issue](https://github.com/microsoft/go/issues/new) if you encounter problems.

## Getting Help

If you need support for an additional platform or encounter issues with a supported platform:

1. Check existing issues with the [Area-Acquisition](https://github.com/microsoft/go/labels/Area-Acquisition) label
2. [File a new issue](https://github.com/microsoft/go/issues/new/choose) if your platform or issue isn't already covered
