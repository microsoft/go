// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package depsinitpanic

import "os"

func init() {
	const v = "MS_GO_UTIL_ALLOW_ONLY_MINIMAL_DEPS"
	if os.Getenv(v) == "1" {
		panic("This command may use more than minimal deps and can't be used while " + v + " is 1")
	}
}
