// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"

	"github.com/microsoft/go/_util/buildutil"
)

// enableSystemWideFIPS enables Mariner and Azure Linux 3 process-wide FIPS mode
// for any process that inherits the current process' environment variables.
func enableSystemWideFIPS() (restore func(), err error) {
	// FIPS mode is enabled if OPENSSL_FORCE_FIPS_MODE is set, regardless of the value.
	_, ok := os.LookupEnv("OPENSSL_FORCE_FIPS_MODE")
	if ok {
		log.Println("Mariner and Azure Linux 3 forced FIPS mode (OPENSSL_FORCE_FIPS_MODE) already enabled.")
		return nil, nil
	}

	buildutil.SetEnv("OPENSSL_FORCE_FIPS_MODE", "1")
	log.Println("Enabled Mariner and Azure Linux 3 FIPS mode (OPENSSL_FORCE_FIPS_MODE).")

	return func() {
		err := os.Unsetenv("OPENSSL_FORCE_FIPS_MODE")
		if err != nil {
			log.Printf("Unable to unset OPENSSL_FORCE_FIPS_MODE: %v\n", err)
			return
		}
		log.Println("Successfully unset OPENSSL_FORCE_FIPS_MODE.")
	}, nil
}
