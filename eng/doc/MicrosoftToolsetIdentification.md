# Microsoft Toolset Identification

Identifying whether a Go binary or toolset is from the Microsoft build of Go or the official Go distribution can be important for diagnostics and verifying expectations.

As of Go 1.25, `go version` and `go version -m` don't clearly indicate the source of the toolset or binary.
We plan to address this: see [microsoft/go#262](https://github.com/microsoft/go/issues/262).
In the meantime, this document describes how to identify a Go program or Go toolset.

## Identifying a Go toolset

If you are able to run `go` commands but aren't sure which distribution `go` is from, you can identify it with these steps.

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

Then, look for a line that contains one of these values:

* `microsoft_systemcrypto=1`
* `GOEXPERIMENT=systemcrypto`

`systemcrypto` is unique to the Microsoft build of Go, so if either of these strings is present, it confirms that the binary is built by the Microsoft build of Go.

If `GOEXPERIMENT=nosystemcrypto` is present (note the `no` prefix), it confirms that the binary was built with the Microsoft build of Go, but `systemcrypto` was explicitly disabled.

If none of the above are present, we can't confirm which build of Go was used.
However, this situation means that the application doesn't meet Microsoft internal crypto policy, which may be enough information in some cases.
