// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t, getenv
#include <string.h> // strnlen

#include "openssl_funcs.h"

#include <openssl/ossl_typ.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>

void* _goboringcrypto_internal_DLOPEN_OPENSSL(void);
int _goboringcrypto_internal_OPENSSL_setup(void);

static inline void*
_goboringcrypto_DLOPEN_OPENSSL(void)
{
	return _goboringcrypto_internal_DLOPEN_OPENSSL();
}

static inline int
_goboringcrypto_OPENSSL_setup(void)
{
    return _goboringcrypto_internal_OPENSSL_setup();
}

// x.x.x, considering the max number of decimal digits for each component
#define MaxVersionStringLength 32
#define OPENSSL_VERSION_3_0_RTM 0x30000000L
#define OPENSSL_VERSION_1_1_1_RTM 0x10101000L
#define OPENSSL_VERSION_1_1_0_RTM 0x10100000L
#define OPENSSL_VERSION_1_0_2_RTM 0x10002000L

#include "apibridge_1_1.h"

enum
{
	GO_NID_X9_62_prime256v1 = NID_X9_62_prime256v1,
	GO_NID_secp384r1 = NID_secp384r1,
	GO_NID_secp521r1 = NID_secp521r1,
	GO_AES_ENCRYPT = 1,
	GO_AES_DECRYPT = 0,
	GO_RSA_PKCS1_PADDING = 1,
	GO_RSA_NO_PADDING = 3,
	GO_RSA_PKCS1_OAEP_PADDING = 4,
	GO_RSA_PKCS1_PSS_PADDING = 6,
};

typedef SHA_CTX GO_SHA_CTX;
typedef SHA256_CTX GO_SHA256_CTX;
typedef SHA512_CTX GO_SHA512_CTX;
typedef EVP_MD GO_EVP_MD;
typedef HMAC_CTX GO_HMAC_CTX;
typedef BN_CTX GO_BN_CTX;
typedef BIGNUM GO_BIGNUM;
typedef EC_GROUP GO_EC_GROUP;
typedef EC_POINT GO_EC_POINT;
typedef EC_KEY GO_EC_KEY;
typedef ECDSA_SIG GO_ECDSA_SIG;
typedef RSA GO_RSA;
typedef BN_GENCB GO_BN_GENCB;
typedef EVP_PKEY GO_EVP_PKEY;
typedef EVP_PKEY_CTX GO_EVP_PKEY_CTX;

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall)      \
    extern ret (*_g_##func)args;                   \
    static inline ret _goboringcrypto_##func args  \
    {                                              \
    	return _g_##func argscall;                 \
    }
#define DEFINEFUNCINTERNAL(ret, func, args, argscall)       \
    extern ret (*_g_internal_##func)args;                   \
    static inline ret _goboringcrypto_internal_##func args  \
    {                                                       \
        return _g_internal_##func argscall;                 \
    }
#define DEFINEFUNC_LEGACY(ret, func, args, argscall)  \
    DEFINEFUNCINTERNAL(ret, func, args, argscall)
#define DEFINEFUNC_110(ret, func, args, argscall)     \
    DEFINEFUNCINTERNAL(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNCINTERNAL(ret, func, args, argscall)
#define DEFINEFUNC_FALLBACK(ret, func, args, argscall)     \
    DEFINEFUNCINTERNAL(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNCINTERNAL
#undef DEFINEFUNC_LEGACY
#undef DEFINEFUNC_110
#undef DEFINEFUNC_RENAMED
#undef DEFINEFUNC_FALLBACK

int _goboringcrypto_stub_openssl_rand(void);
int _goboringcrypto_restore_openssl_rand(void);
int _goboringcrypto_EVP_AES_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);
void _goboringcrypto_EVP_AES_cbc_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *arg0, uint8_t *arg1, size_t arg2, const uint8_t *a, const int arg5);
void EVP_AES_cbc_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);
void EVP_AES_cbc_dec(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);
int _goboringcrypto_RSA_generate_key_fips(GO_RSA *, int, GO_BN_GENCB *);
int _goboringcrypto_RSA_sign_pss_mgf1(
	GO_RSA *, unsigned int *out_len,
    uint8_t *out, unsigned int max_out,
	const uint8_t *in, unsigned int in_len,
	GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len);
int _goboringcrypto_RSA_verify_pss_mgf1(
	GO_RSA *, const uint8_t *msg,
	unsigned int msg_len, GO_EVP_MD *md,
	const GO_EVP_MD *mgf1_md, int salt_len,
	const uint8_t *sig, unsigned int sig_len);

static inline void
_goboringcrypto_EVP_AES_ctr128_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t in_len)
{
	int len;
	_goboringcrypto_EVP_EncryptUpdate(ctx, out, &len, in, in_len);
}

static inline int
_goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX *dest, const GO_HMAC_CTX *src)
{
    return _goboringcrypto_HMAC_CTX_copy(dest, (GO_HMAC_CTX *) src);
}

static inline int
_goboringcrypto_EVP_MD_type(const GO_EVP_MD *md)
{
	return _goboringcrypto_internal_EVP_MD_get_type(md);
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_md5_sha1(void)
{
	return _goboringcrypto_internal_EVP_md5_sha1();
}

static inline void
_goboringcrypto_HMAC_CTX_free(HMAC_CTX *ctx)
{
	_goboringcrypto_internal_HMAC_CTX_free(ctx);
}

static inline size_t
_goboringcrypto_HMAC_size(const GO_HMAC_CTX* arg0)
{
	const EVP_MD* md = _goboringcrypto_internal_HMAC_CTX_get_md(arg0);
	return _goboringcrypto_internal_EVP_MD_get_size(md);
}

static inline GO_HMAC_CTX*
_goboringcrypto_HMAC_CTX_new(void)
{
	return _goboringcrypto_internal_HMAC_CTX_new();
}

static inline void
_goboringcrypto_HMAC_CTX_reset(GO_HMAC_CTX* ctx)
{
	_goboringcrypto_internal_HMAC_CTX_reset(ctx);
}

static inline unsigned int
_goboringcrypto_BN_num_bytes(const GO_BIGNUM* a)
{
	return ((_goboringcrypto_internal_BN_num_bits(a)+7)/8);
}

static inline int
_goboringcrypto_RSA_set0_factors(GO_RSA * r, GO_BIGNUM *p, GO_BIGNUM *q)
{
	return _goboringcrypto_internal_RSA_set0_factors(r, p, q);
}

static inline int
_goboringcrypto_RSA_set0_crt_params(GO_RSA * r, GO_BIGNUM *dmp1, GO_BIGNUM *dmq1, GO_BIGNUM *iqmp)
{
	return _goboringcrypto_internal_RSA_set0_crt_params(r, dmp1, dmq1, iqmp);
}

static inline void
_goboringcrypto_RSA_get0_crt_params(const GO_RSA *r, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmq1, const GO_BIGNUM **iqmp)
{
	_goboringcrypto_internal_RSA_get0_crt_params(r, dmp1, dmq1, iqmp);
}

static inline int
_goboringcrypto_RSA_set0_key(GO_RSA * r, GO_BIGNUM *n, GO_BIGNUM *e, GO_BIGNUM *d)
{
	return _goboringcrypto_internal_RSA_set0_key(r, n, e, d);
}

static inline void 
_goboringcrypto_RSA_get0_factors(const GO_RSA *rsa, const GO_BIGNUM **p, const GO_BIGNUM **q)
{
	_goboringcrypto_internal_RSA_get0_factors(rsa, p, q);
}

static inline void 
_goboringcrypto_RSA_get0_key(const GO_RSA *rsa, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d)
{
	_goboringcrypto_internal_RSA_get0_key(rsa, n, e, d);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX* ctx, int pad)
{
	return _goboringcrypto_internal_RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX *ctx, uint8_t *l, int llen)
{
	return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)l);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX *ctx, const GO_EVP_MD *md)
{
	return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX * arg0, int arg1)
{
	return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(arg0, EVP_PKEY_RSA, 
		(EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), 
		EVP_PKEY_CTRL_RSA_PSS_SALTLEN, 
		arg1, NULL);
}

static inline int
_goboringcrypto_internal_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
	return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0, (void *)md);
}
static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX * ctx, const GO_EVP_MD *md)
{
	return _goboringcrypto_internal_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,
		EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
		EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)md);
}
