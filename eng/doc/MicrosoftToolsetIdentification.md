# Microsoft Toolset Identification

Identifying whether a Go binary or toolset is from the Microsoft build of Go or the official Go distribution can be important for diagnostics and verifying expectations.

As of Go 1.25, `go version` and `go version -m` don't clearly indicate the source of the toolset or binary.

As of Go 1.26, setting `GODEBUG=ms_version=1` makes `go version` report the Microsoft build version string.
`go version -m <program>` on a `program` built by the Microsoft build of Go always includes a `microsoft_toolset_version` line specifying the Microsoft version.

> [!TIP]
> If you always set `GODEBUG=ms_version=1`, you will always have the most reliable information available.
> If the toolset doesn't support this setting, it will simply be ignored.

The below sections provide step-by-step processes to help identify a Microsoft build of Go toolset and binaries built by it.

## Identifying a Go toolset

If you are able to run `go` commands but aren't sure which distribution `go` is from, you can identify it with these lists of steps.

First, run `go version`.
If the output is 1.26 or later, then:

1. Run `GODEBUG=ms_version=1 go version`.
    * If the output includes the `-microsoft` suffix, it's the Microsoft build of Go.
    * Otherwise, it isn't.

If the output is 1.25 or earlier, then:

1. Run `go env GOROOT` to find the root directory of the toolset.
    * If the path contains clues, it might be clear already which toolset this is.
1. Go to the path and read the content of the `go.env` file.
1. Look for the `GOTOOLCHAIN` setting.
    * If it's `GOTOOLCHAIN=local`, it's likely the Microsoft build of Go. To confirm, read the comment above this line, which should mention Microsoft.
    * If it's `GOTOOLCHAIN=auto`, it's not the Microsoft build of Go.


## Examining Go binaries

First, read the version data from your application binary:

```sh
go version -m <your-application>
```

Then, look for a line that contains `microsoft_toolset_version`.

  * The presence of this line confirms that the binary was built by the Microsoft build of Go. It also shows you the version and revision used.
  * Unfortunately, this is only available if the binary was built with Microsoft build of Go 1.26 or later.

Otherwise, look for one of these clues:

* `microsoft_systemcrypto=1`
* `GOEXPERIMENT=systemcrypto`

`systemcrypto` is unique to the Microsoft build of Go, so if either of these strings is present, it confirms that the binary is built by the Microsoft build of Go.

If `GOEXPERIMENT=nosystemcrypto` is present (note the `no` prefix), it also confirms that the binary was built with the Microsoft build of Go, but it shows that `systemcrypto` was explicitly disabled.

If none of the above are present, we can't confirm which build of Go was used.
However, this situation means that the application doesn't meet Microsoft internal crypto policy, which may be enough information in some cases.
