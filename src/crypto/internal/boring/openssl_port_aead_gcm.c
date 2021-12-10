// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !no_openssl && !cmd_go_bootstrap && !msan
// +build linux,!android,!no_openssl,!cmd_go_bootstrap,!msan

#include "goboringcrypto.h"
#include <openssl/err.h>

int
_goboringcrypto_EVP_CIPHER_CTX_seal(
    EVP_CIPHER_CTX *ctx, uint8_t *out,
    uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_len,
    size_t *ciphertext_len)
{
    int len;

    if (plaintext_len == 0)
        plaintext = "";

    if (aad_len == 0)
        aad = "";

    // Provide AAD data.
    if (!_goboringcrypto_internal_EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return 0;

    if (!_goboringcrypto_internal_EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len))
        return 0;
    *ciphertext_len = len;

    if (!_goboringcrypto_internal_EVP_EncryptFinal_ex(ctx, out + len, &len))
        return 0;
    *ciphertext_len += len;

    if (!_goboringcrypto_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out+(*ciphertext_len)))
        return 0;
    *ciphertext_len += 16;

    return 1;
}
