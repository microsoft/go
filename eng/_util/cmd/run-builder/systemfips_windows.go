// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/registry"
)

// enableSystemWideFIPS enables Windows system-wide FIPS and returns a state-restoring func in case
// the host will be used later by another process. If the host is simultaneously shared, enabling
// system-wide FIPS may interfere because this policy is a machine setting.
func enableSystemWideFIPS() (restore func(), err error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}

	enabled, enabledType, err := key.GetIntegerValue("Enabled")
	if err != nil {
		return nil, err
	}

	if enabledType != registry.DWORD {
		return nil, fmt.Errorf("unexpected FIPS algorithm policy Enabled key type: %v", enabledType)
	}

	if enabled == 1 {
		log.Println("FIPS algorithm policy already enabled.")
		return nil, nil
	}

	log.Printf("Found FIPS algorithm policy Enabled value: %v\n", enabled)
	if err := key.SetDWordValue("Enabled", 1); err != nil {
		return nil, err
	}

	log.Println("Enabled FIPS algorithm policy.")

	return func() {
		defer key.Close()
		err := key.SetDWordValue("Enabled", uint32(enabled))
		if err != nil {
			log.Printf("Unable to set FIPS algorithm policy to original value %v: %v\n", enabled, err)
			return
		}
		log.Printf("Successfully reset FIPS algorithm policy back to original value %v: %v\n", enabled, err)
	}, nil
}
