//go:build go1.25 && !cmd_go_bootstrap

package openssl

import (
	"hash"
)

type HashCloner = hash.Cloner
