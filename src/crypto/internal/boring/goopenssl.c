// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !no_openssl && !cmd_go_bootstrap && !msan
// +build linux,!android,!no_openssl,!cmd_go_bootstrap,!msan

#include "goopenssl.h"

#include <dlfcn.h>
#include <stdio.h>

// Approach taken from .Net System.Security.Cryptography.Native
// https://github.com/dotnet/runtime/blob/f64246ce08fb7a58221b2b7c8e68f69c02522b0d/src/libraries/Native/Unix/System.Security.Cryptography.Native/opensslshim.c

static void* handle = NULL;

// Load all the functions stored in FOR_ALL_OPENSSL_FUNCTIONS
// and asign them to their correspoding function pointer
// defined in goopenssl.h.
static void
_goboringcrypto_load_openssl_functions(const void* v1_0_sentinel)
{
    // This function could be called concurrently from different Goroutines unless correctly locked.
    // If that happen there could be a race in DEFINEFUNC_RENAMED where the global function pointer is NULL,
    // then properly loaded, then goes back to NULL right before being used (then loaded again).
    // To avoid this situation only assign the function pointer when the function has been successfully
    // loaded in tmp_ptr.
    void* tmp_ptr;

#define DEFINEFUNC(ret, func, args, argscall) \
    _g_##func = dlsym(handle, #func);         \
    if (_g_##func == NULL) { fprintf(stderr, "Cannot get required symbol " #func " from libcrypto\n"); abort(); }
#define DEFINEFUNCINTERNAL(ret, func, args, argscall) \
    _g_internal_##func = dlsym(handle, #func);        \
    if (_g_internal_##func == NULL) { fprintf(stderr, "Cannot get required symbol " #func " from libcrypto\n"); abort(); }
#define DEFINEFUNC_LEGACY(ret, func, args, argscall)  \
    if (v1_0_sentinel != NULL)                        \
    {                                                 \
        DEFINEFUNCINTERNAL(ret, func, args, argscall) \
    }
#define DEFINEFUNC_110(ret, func, args, argscall)     \
    if (v1_0_sentinel == NULL)                        \
    {                                                 \
        DEFINEFUNCINTERNAL(ret, func, args, argscall) \
    }
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall)                                              \
    tmp_ptr = dlsym(handle, #func);                                                                         \
    if (tmp_ptr == NULL)                                                                                    \
    {                                                                                                       \
        tmp_ptr = dlsym(handle, #oldfunc);                                                                  \
        if (tmp_ptr == NULL)                                                                                \
        {                                                                                                   \
            fprintf(stderr, "Cannot get required symbol " #func " nor " #oldfunc " from libcrypto\n");      \
            abort();                                                                                        \
        }                                                                                                   \
    }                                                                                                       \
    _g_internal_##func = tmp_ptr;
#define DEFINEFUNC_FALLBACK(ret, func, args, argscall)      \
    tmp_ptr = dlsym(handle, #func);                         \
    if (tmp_ptr == NULL) { tmp_ptr = (void*)local_##func; } \
    _g_internal_##func = tmp_ptr;

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNCINTERNAL
#undef DEFINEFUNC_LEGACY
#undef DEFINEFUNC_110
#undef DEFINEFUNC_RENAMED
#undef DEFINEFUNC_FALLBACK
}

#define SONAME_BASE "libcrypto.so."
#define MAKELIB(v) SONAME_BASE v

static void
_goboringcrypto_DLOPEN(const char* libraryName)
{
    handle = dlopen(libraryName, RTLD_LAZY | RTLD_GLOBAL);
}

void*
_goboringcrypto_internal_DLOPEN_OPENSSL(void)
{
    if (handle)
    {
        return handle;
    }

    // If there is an override of the version specified using the GO_OPENSSL_VERSION_OVERRIDE
    // env variable, try to load that first.
    // The format of the value in the env variable is expected to be the version numbers,
    // like 1.0.0, 1.0.2 etc.
    char* versionOverride = getenv("GO_OPENSSL_VERSION_OVERRIDE");
    if ((versionOverride != NULL) && strnlen(versionOverride, MaxVersionStringLength + 1) <= MaxVersionStringLength)
    {
        char soName[sizeof(SONAME_BASE) + MaxVersionStringLength] = SONAME_BASE;
        strcat(soName, versionOverride);
        _goboringcrypto_DLOPEN(soName);
    }

    if (handle == NULL)
    {
        _goboringcrypto_DLOPEN(MAKELIB("3"));
    }

    if (handle == NULL)
    {
        _goboringcrypto_DLOPEN(MAKELIB("1.1"));
    }

    // FreeBSD uses a different suffix numbering convention.
    // Current supported FreeBSD releases should use the order .11 -> .111
    if (handle == NULL)
    {
        _goboringcrypto_DLOPEN(MAKELIB("11"));
    }

    if (handle == NULL)
    {
        _goboringcrypto_DLOPEN(MAKELIB("111"));
    }

    if (handle == NULL)
    {
        // Debian 9 has dropped support for SSLv3 and so they have bumped their soname. Let's try it
        // before trying the version 1.0.0 to make it less probable that some of our other dependencies
        // end up loading conflicting version of libcrypto.
        _goboringcrypto_DLOPEN(MAKELIB("1.0.2"));
    }

    if (handle == NULL)
    {
        // Now try the default versioned so naming as described in the OpenSSL doc
        _goboringcrypto_DLOPEN(MAKELIB("1.0.0"));
    }

    if (handle == NULL)
    {
        // Fedora derived distros use different naming for the version 1.0.0
        _goboringcrypto_DLOPEN(MAKELIB("10"));
    }

    return handle;
}

int _goboringcrypto_internal_OPENSSL_thread_setup(void);

int
_goboringcrypto_internal_OPENSSL_setup(void) 
{
    // A function defined in libcrypto.so.1.0.x that is not defined in libcrypto.so.1.1.0
    const void* v1_0_sentinel = dlsym(handle, "EVP_MD_CTX_cleanup");
    _goboringcrypto_load_openssl_functions(v1_0_sentinel);
    // OPENSSL_init initialize FIPS callbacks and rand generator.
    // no-op from OpenSSL 1.1.1 onwards.
    _goboringcrypto_internal_OPENSSL_init();
    
    if (v1_0_sentinel != NULL)
    {
        if (_goboringcrypto_internal_OPENSSL_thread_setup() != 1)
        {
            return 0;
        }
        // Load all algorithms and the openssl configuration file.
        _goboringcrypto_internal_OPENSSL_add_all_algorithms_conf();

        // Ensure that the error message table is loaded.
        _goboringcrypto_internal_ERR_load_crypto_strings();
        return 1;
    }
    else
    {
        // In OpenSSL 1.0 we call OPENSSL_add_all_algorithms_conf() and ERR_load_crypto_strings(),
        // so do the same for 1.1
        return _goboringcrypto_internal_OPENSSL_init_crypto(
                OPENSSL_INIT_ADD_ALL_CIPHERS |
                OPENSSL_INIT_ADD_ALL_DIGESTS |
                OPENSSL_INIT_LOAD_CONFIG |
                OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                NULL);
    }
}
