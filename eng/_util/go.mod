// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

module github.com/microsoft/go/_util

go 1.16

require (
	github.com/microsoft/go-infra v0.0.0-20231219225928-f2e20f366e2d
	github.com/microsoft/go/_core v0.0.0
	golang.org/x/sys v0.13.0
	gotest.tools/gotestsum v1.6.5-0.20210515201937-ecb7c6956f6d
)

replace github.com/microsoft/go/_core => ../_core
