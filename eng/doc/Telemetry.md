# Telemetry in the Microsoft build of Go

The Microsoft build of Go collects opt-out (enabled by default) toolset telemetry.
Telemetry is sent to Microsoft via Azure Application Insights when `go build`, `go install`, or `go run` is executed.
No telemetry is collected for other `go` subcommands (e.g. `go test`, `go vet`, `go fmt`).

For the blog post announcing this feature, see [Microsoft build of Go Telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/).

## What is collected

Telemetry data consists of **counters** (simple event names that are incremented) and **properties** (key-value custom dimensions attached to a counter event).
No source code, file paths, module contents, or personally identifiable information is collected.
Each telemetry session is assigned a random session ID that cannot be linked back to a user.

The counters and properties collected are defined in the [telemetry upload configuration](https://github.com/microsoft/go-infra/blob/main/telemetry/config/config.json) and are listed below.

### Invocation counter

| Counter | Description |
|---|---|
| `go/invocations` | Incremented once per `go` command invocation. |

#### Properties on `go/invocations`

| Property | Description |
|---|---|
| `msgo/module/hash` | A SHA-256 hash of the Go module path from the nearest `go.mod` file, found using [`modload.FindGoMod`](https://pkg.go.dev/cmd/go/internal/modload#FindGoMod). Only sent when a `go.mod` file is found. |

### Subcommand

| Counter | Description |
|---|---|
| `go/subcommand:{build,install,run}` | Which subcommand was used. |

### Target platform

| Counter | Description |
|---|---|
| `go/platform/target/port:<GOOS>-<GOARCH>` | The target platform port (e.g. `linux-amd64`, `windows-arm64`). |
| `go/cgo:{enabled,disabled}` | Whether cgo was enabled for the build. |

### GOEXPERIMENT settings

| Counter | Description |
|---|---|
| `go/goexperiment:<name>` | Each active `GOEXPERIMENT` value that differs from the baseline. Only Microsoft-specific experiments are uploaded: `systemcrypto`, `nosystemcrypto`, `opensslcrypto`, `cngcrypto`, `darwincrypto`, `ms_nocgo_opensslcrypto`, and `ms_tls_config_schannel`. |

### CI environment detection

| Counter | Description |
|---|---|
| `msgo/ci:<provider>` | Detected CI provider, if any. Values: `azdo`, `github`, `gitlab`, `appveyor`, `travis`, `circleci`, `aws_codebuild`, `jenkins`, `teamcity`, `google_cloud_build`. Detection is based on well-known environment variables set by each CI system. |

### System cryptography

| Counter | Description |
|---|---|
| `msgo/systemcrypto:{enabled,disabled}` | Whether the system cryptography backend is enabled. |

## What is NOT collected

- No source code or file contents.
- No file paths from the local file system.
- No textual module names or paths (a one-way SHA-256 hash of the module path is collected).
- No environment variable values (only the presence of specific CI-related variables is checked).
- No network or authentication information.
- No personally identifiable information (PII).

## How to opt out

> [!NOTE]
> Configuration through `go env -w` and `$GOROOT/go.env` is supported starting with Microsoft build of Go `v1.27.2-2`.
> In earlier versions, the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED` process environment variable is the only way to configure the Microsoft-specific telemetry collection.

The Microsoft build of Go sets `MS_GOTOOLCHAIN_TELEMETRY_ENABLED=1` in `$GOROOT/go.env`.
An effective value of `1` enables telemetry collection and sends data to Application Insights.
An effective value of `0` completely disables telemetry collection and sends no data.

Users can override the installation default with the standard Go environment configuration:

```shell
go env -w MS_GOTOOLCHAIN_TELEMETRY_ENABLED=0
```

To override the setting for an individual process, set the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED` environment variable to `0` when starting the process.

Configuration is resolved in this order, from highest to lowest precedence:

1. The process environment.
2. The user's `GOENV` file, managed with `go env -w` and `go env -u`.
3. The installation-wide `$GOROOT/go.env` file.

> [!NOTE]
> This setting only controls Microsoft-specific telemetry. The upstream Go toolchain has its own [telemetry system](https://go.dev/doc/telemetry) controlled separately via `go telemetry`.

## Privacy

Microsoft's privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704.

See the [Data Collection policy](/README.md#data-collection) in the repository README for more information.
