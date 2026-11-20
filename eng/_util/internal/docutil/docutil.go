// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docutil

import "strings"

// IsCopied reports whether contents start with the automatic documentation copy notice.
func IsCopied(contents []byte) bool {
	normalized := strings.ReplaceAll(string(contents), "\r\n", "\n")
	return strings.HasPrefix(normalized, "<!--\nDO NOT EDIT THIS COPY.\nLocal edits will be overwritten.")
}
