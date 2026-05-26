# Telemetry in the Microsoft build of Go

The Microsoft build of Go collects opt-out (enabled by default) toolset telemetry.
Telemetry is sent to Microsoft via Azure Application Insights when `go build`, `go install`, or `go run` is executed.
No telemetry is collected for other `go` subcommands (e.g. `go test`, `go vet`, `go fmt`).

For the blog post announcing this feature, see [Microsoft Go Telemetry](https://devblogs.microsoft.com/go/microsoft-go-telemetry/).

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
| `msgo/module/hash` | A SHA-256 hash of the Go module path from the nearest `go.mod` file. This is a one-way hash — the original module path cannot be recovered from it. Only sent when a `go.mod` file is found in the current directory or a parent directory. |

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
| `msgo/systemcrypto:{enabled,disabled}` | Whether the system cryptography backend is enabled on platforms that support it. |

## What is NOT collected

- No source code or file contents.
- No file paths from the local file system.
- No module names or paths — only a one-way SHA-256 hash of the module path is collected.
- No environment variable values (only the presence of specific CI-related variables is checked).
- No network or authentication information.
- No personally identifiable information (PII).

## How to opt out

Set the `MS_GOTOOLCHAIN_TELEMETRY_ENABLED` environment variable to `0`.

This completely disables Microsoft telemetry collection. When disabled, no data is sent to Application Insights.

> [!NOTE]
> This setting only controls Microsoft-specific telemetry. The upstream Go toolchain has its own [telemetry system](https://go.dev/doc/telemetry) controlled separately via `go telemetry`.

## Privacy

Microsoft's privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704.

See the [Data Collection policy](/README.md#data-collection) in the repository README for more information.
