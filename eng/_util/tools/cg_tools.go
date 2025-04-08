// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build tools

package tools

// Work around Go detector false positives: import dependencies just so that we can upgrade
// them. See https://github.com/microsoft/component-detection/issues/1333

import (
	_ "github.com/golang-jwt/jwt/v5"
	_ "golang.org/x/net/http2"
)
