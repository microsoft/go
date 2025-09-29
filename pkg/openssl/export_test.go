package openssl

import "sync"

var ErrOpen = errOpen

var SymCryptProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("symcryptprovider")
})

var FIPSProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("fips")
})

var DefaultProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("default")
})
