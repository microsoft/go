// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android
// +build linux,!android

#include "goopenssl.h"
#include "apibridge_1_1.h"

// Minimally define the structs from 1.0.x which went opaque in 1.1.0 for the
// portable build building against the 1.1.x headers
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0_RTM
// The crypto_ex_data_st struct is smaller in 1.1, which changes the packing of
// dsa_st
struct crypto_ex_data_10_st
{
    STACK_OF(void) * sk;
    int dummy;
};

struct hmac_ctx_st
{
    const EVP_MD *md;
    const void* _ignored0;
    const void* _ignored1;
    const void* _ignored2;
    unsigned int _ignored3;
    unsigned char _ignored4[128];
};
struct rsa_st
{
    int _ignored0;
    long _ignored1;
    const void* _ignored2;
    const void* _ignored3;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
    struct crypto_ex_data_10_st _ignored4;
    int _ignored5;
    int _ignored6;
};
struct evp_md_ctx_st {
    const void *_ignored0;
    void *_ignored1;
    unsigned long _ignored2;
    void *md_data;
    void *_ignored3;
    int (*_ignored4) (void *ctx, const void *data, size_t count);
};
struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    /* FIXME: prototype these some day */
    int (*sign) (int type, const unsigned char *m, unsigned int m_length,
                 unsigned char *sigret, unsigned int *siglen, void *key);
    int (*verify) (int type, const unsigned char *m, unsigned int m_length,
                   const unsigned char *sigbuf, unsigned int siglen,
                   void *key);
    int required_pkey_type[5];  /* EVP_PKEY_xxx */
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
};
#define EVP_PKEY_NULL_method    NULL,NULL,{0,0,0,0}
#endif

void
local_HMAC_CTX_free(HMAC_CTX* ctx)
{
    if (ctx != NULL)
    {
        _goboringcrypto_internal_HMAC_CTX_cleanup(ctx);
        free(ctx);
    }
}

void*
local_EVP_MD_CTX_md_data(EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

const EVP_MD*
local_HMAC_CTX_get_md(const HMAC_CTX* ctx)
{
    return ctx->md;
}

HMAC_CTX*
local_HMAC_CTX_new()
{
    HMAC_CTX* ctx = malloc(sizeof(HMAC_CTX));
    if (ctx)
    {
        _goboringcrypto_internal_HMAC_CTX_init(ctx);
    }

    return ctx;
}

void
local_HMAC_CTX_reset(HMAC_CTX* ctx) {
    _goboringcrypto_internal_HMAC_CTX_cleanup(ctx);
    _goboringcrypto_internal_HMAC_CTX_init(ctx);
}

struct md5_sha1_ctx {
  MD5_CTX md5;
  SHA_CTX sha1;
};

static int
md5_sha1_init(EVP_MD_CTX *ctx)
{
  struct md5_sha1_ctx *mctx = _goboringcrypto_internal_EVP_MD_CTX_md_data(ctx);
  if (!_goboringcrypto_internal_MD5_Init(&mctx->md5))
    return 0;
  return _goboringcrypto_SHA1_Init(&mctx->sha1);
}

static int md5_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  struct md5_sha1_ctx *mctx = _goboringcrypto_internal_EVP_MD_CTX_md_data(ctx);
  if (!_goboringcrypto_internal_MD5_Update(&mctx->md5, data, count))
    return 0;
  return _goboringcrypto_SHA1_Update(&mctx->sha1, data, count);
}

static int md5_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  struct md5_sha1_ctx *mctx = _goboringcrypto_internal_EVP_MD_CTX_md_data(ctx);
  if (!_goboringcrypto_internal_MD5_Final(md, &mctx->md5))
    return 0;
  return _goboringcrypto_SHA1_Final(md + MD5_DIGEST_LENGTH, &mctx->sha1);
}

// Change: Removed:
// static int ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
    0,
    md5_sha1_init,
    md5_sha1_update,
    md5_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method, // Change: inserted
    MD5_CBLOCK,
    sizeof(EVP_MD *) + sizeof(struct md5_sha1_ctx),
    NULL, // Change: was ctrl
};

const EVP_MD* local_EVP_md5_sha1(void)
{
  return &md5_sha1_md;
}

int
local_RSA_set0_crt_params(RSA * r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

void
local_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int
local_RSA_set0_key(RSA * r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) 
    {
        _goboringcrypto_BN_free(r->n);
        r->n = n;
    }
    if (e != NULL)
    {
        _goboringcrypto_BN_free(r->e);
        r->e = e;
    }
    if (d != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->d);
        r->d = d;
    }

    return 1;
}

int
local_RSA_set0_factors(RSA * r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->p);
        r->p = p;
    }
    if (q != NULL)
    {
        _goboringcrypto_internal_BN_clear_free(r->q);
        r->q = q;
    }

    return 1;
}

void 
local_RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q)
{
    if (p)
        *p = rsa->p;
    if (q)
        *q = rsa->q;
}

void 
local_RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n)
        *n = rsa->n;
    if (e)
        *e = rsa->e;
    if (d)
        *d = rsa->d;
}

int
local_RSA_pkey_ctx_ctrl(EVP_PKEY_CTX* ctx, int optype, int cmd, int p1, void* p2)
{
    return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, optype, cmd, p1, p2);
}