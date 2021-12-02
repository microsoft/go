//go:build linux && !android && !no_openssl && !cmd_go_bootstrap && !msan
// +build linux,!android,!no_openssl,!cmd_go_bootstrap,!msan

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

// List of all functions from the libcrypto that are used in the crypto/internal/boring.
// Forgetting to add a function here results in build failure with message reporting the function
// that needs to be added.
//
// The purpose of FOR_ALL_OPENSSL_FUNCTIONS is to define all libcrypto functions
// without depending on the openssl headers so it is easier to use this package
// with an openssl version different that the one used at build time.
//
// The following macros may not be defined at this point,
// they are not resolved here but just accumulated in FOR_ALL_OPENSSL_FUNCTIONS.
//
// DEFINEFUNC defines and loads openssl functions that can be directly called from Go as their signature match
// the boringssl and do not require special logic.
// The process will be aborted if the function can't be loaded.
//
// DEFINEFUNCINTERNAL defines and loads openssl functions that will be wrapped due to signature incompatibility or
// because it does not exist in all supported openssl versions.
// The process will be aborted if the function can't be loaded.
//
// DEFINEFUNC_LEGACY acts like DEFINEFUNCINTERNAL but only aborts the process if function can't be loaded
// when using 1.0.x. This indicates the function is required when using 1.0.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_110 acts like DEFINEFUNCINTERNAL but only aborts the process if function can't be loaded
// when using 1.1.0 or higher.
//
// DEFINEFUNC_RENAMED acts like DEFINEFUNCINTERNAL but if the function can't be loaded it will try with another
// function name, as in some versions jumps openssl has renamed functions without changing the signatur.
// The process will be aborted if neither function can be loaded.
//
#define FOR_ALL_OPENSSL_FUNCTIONS \
DEFINEFUNC(unsigned long, ERR_get_error, (void), ()) \
DEFINEFUNC(void, ERR_error_string_n, (unsigned long e, unsigned char *buf, size_t len), (e, buf, len)) \
DEFINEFUNCINTERNAL(int, RAND_poll, (void), ()) \
DEFINEFUNCINTERNAL(void, OPENSSL_init, (void), ()) \
DEFINEFUNC_LEGACY(void, ERR_load_crypto_strings, (void), ()) \
DEFINEFUNC_LEGACY(int, CRYPTO_num_locks, (void), ()) \
DEFINEFUNC_LEGACY(void, CRYPTO_set_id_callback, (unsigned long (*id_function)(void)), (id_function)) \
DEFINEFUNC_LEGACY(void, CRYPTO_set_locking_callback, \
    (void (*locking_function)(int mode, int n, const char *file, int line)),  \
    (locking_function)) \
DEFINEFUNC_LEGACY(void, OPENSSL_add_all_algorithms_conf, (void), ()) \
DEFINEFUNC_110(int, OPENSSL_init_crypto, (uint64_t ops, const void *settings), (ops, settings)) \
DEFINEFUNC(int, FIPS_mode, (void), ()) \
DEFINEFUNC(int, FIPS_mode_set, (int r), (r)) \
DEFINEFUNCINTERNAL(int, RAND_set_rand_method, (const RAND_METHOD *rand), (rand)) \
DEFINEFUNCINTERNAL(RAND_METHOD*, RAND_get_rand_method, (void), ()) \
DEFINEFUNC(int, RAND_bytes, (uint8_t * arg0, size_t arg1), (arg0, arg1)) \
DEFINEFUNC(int, SHA1_Init, (GO_SHA_CTX * arg0), (arg0)) \
DEFINEFUNC(int, SHA1_Update, (GO_SHA_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, SHA1_Final, (uint8_t * arg0, GO_SHA_CTX *arg1), (arg0, arg1)) \
DEFINEFUNC(int, SHA224_Init, (GO_SHA256_CTX * arg0), (arg0)) \
DEFINEFUNC(int, SHA224_Update, (GO_SHA256_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, SHA224_Final, (uint8_t * arg0, GO_SHA256_CTX *arg1), (arg0, arg1)) \
DEFINEFUNC(int, SHA256_Init, (GO_SHA256_CTX * arg0), (arg0)) \
DEFINEFUNC(int, SHA256_Update, (GO_SHA256_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, SHA256_Final, (uint8_t * arg0, GO_SHA256_CTX *arg1), (arg0, arg1)) \
DEFINEFUNC(int, SHA384_Init, (GO_SHA512_CTX * arg0), (arg0)) \
DEFINEFUNC(int, SHA384_Update, (GO_SHA512_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, SHA384_Final, (uint8_t * arg0, GO_SHA512_CTX *arg1), (arg0, arg1)) \
DEFINEFUNC(int, SHA512_Init, (GO_SHA512_CTX * arg0), (arg0)) \
DEFINEFUNC(int, SHA512_Update, (GO_SHA512_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, SHA512_Final, (uint8_t * arg0, GO_SHA512_CTX *arg1), (arg0, arg1)) \
DEFINEFUNC(const GO_EVP_MD *, EVP_md5, (void), ()) \
DEFINEFUNC(const GO_EVP_MD *, EVP_sha1, (void), ()) \
DEFINEFUNC(const GO_EVP_MD *, EVP_sha224, (void), ()) \
DEFINEFUNC(const GO_EVP_MD *, EVP_sha256, (void), ()) \
DEFINEFUNC(const GO_EVP_MD *, EVP_sha384, (void), ()) \
DEFINEFUNC(const GO_EVP_MD *, EVP_sha512, (void), ()) \
DEFINEFUNC_RENAMED(int, EVP_MD_get_type, EVP_MD_type, (const GO_EVP_MD *arg0), (arg0)) \
DEFINEFUNC_RENAMED(size_t, EVP_MD_get_size, EVP_MD_size, (const GO_EVP_MD *arg0), (arg0)) \
DEFINEFUNC_110(const GO_EVP_MD*, EVP_md5_sha1, (void), ()) \
DEFINEFUNCINTERNAL(int, MD5_Init, (MD5_CTX *c), (c)) \
DEFINEFUNCINTERNAL(int, MD5_Update, (MD5_CTX *c, const void *data, size_t len), (c, data, len)) \
DEFINEFUNCINTERNAL(int, MD5_Final, (unsigned char *md, MD5_CTX *c), (md, c)) \
DEFINEFUNC_LEGACY(void, HMAC_CTX_init, (GO_HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC_LEGACY(void, HMAC_CTX_cleanup, (GO_HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC(int, HMAC_Init_ex, \
           (GO_HMAC_CTX * arg0, const void *arg1, int arg2, const GO_EVP_MD *arg3, ENGINE *arg4), \
           (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, HMAC_Update, (GO_HMAC_CTX * arg0, const uint8_t *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, HMAC_Final, (GO_HMAC_CTX * arg0, uint8_t *arg1, unsigned int *arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(size_t, HMAC_CTX_copy, (GO_HMAC_CTX *dest, GO_HMAC_CTX *src), (dest, src)) \
DEFINEFUNC_110(void, HMAC_CTX_free, (GO_HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC_110(EVP_MD*, HMAC_CTX_get_md, (const GO_HMAC_CTX* ctx), (ctx)) \
DEFINEFUNC_110(GO_HMAC_CTX*, HMAC_CTX_new, (void), ()) \
DEFINEFUNC_110(void, HMAC_CTX_reset, (GO_HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC(EVP_CIPHER_CTX *, EVP_CIPHER_CTX_new, (void), ()) \
DEFINEFUNC(int, EVP_CIPHER_CTX_set_padding, (EVP_CIPHER_CTX *x, int padding), (x, padding)) \
DEFINEFUNC(int, EVP_CipherInit_ex, \
           (EVP_CIPHER_CTX * ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc), \
           (ctx, type, impl, key, iv, enc)) \
DEFINEFUNC(int, EVP_CipherUpdate, \
           (EVP_CIPHER_CTX * ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), \
           (ctx, out, outl, in, inl)) \
DEFINEFUNC(GO_BIGNUM *, BN_new, (void), ()) \
DEFINEFUNC(void, BN_free, (GO_BIGNUM * arg0), (arg0)) \
DEFINEFUNCINTERNAL(void, BN_clear_free, (GO_BIGNUM * arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, BN_set_word, (BIGNUM *a, BN_ULONG w), (a, w)) \
DEFINEFUNCINTERNAL(unsigned int, BN_num_bits, (const GO_BIGNUM *arg0), (arg0)) \
DEFINEFUNC(GO_BIGNUM *, BN_bin2bn, (const uint8_t *arg0, size_t arg1, GO_BIGNUM *arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(size_t, BN_bn2bin, (const GO_BIGNUM *arg0, uint8_t *arg1), (arg0, arg1)) \
DEFINEFUNC(void, EC_GROUP_free, (GO_EC_GROUP * arg0), (arg0)) \
DEFINEFUNC(GO_EC_POINT *, EC_POINT_new, (const GO_EC_GROUP *arg0), (arg0)) \
DEFINEFUNC(void, EC_POINT_free, (GO_EC_POINT * arg0), (arg0)) \
DEFINEFUNC(int, EC_POINT_get_affine_coordinates_GFp, \
           (const GO_EC_GROUP *arg0, const GO_EC_POINT *arg1, GO_BIGNUM *arg2, GO_BIGNUM *arg3, GO_BN_CTX *arg4), \
           (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EC_POINT_set_affine_coordinates_GFp, \
           (const GO_EC_GROUP *arg0, GO_EC_POINT *arg1, const GO_BIGNUM *arg2, const GO_BIGNUM *arg3, GO_BN_CTX *arg4), \
           (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(GO_EC_KEY *, EC_KEY_new_by_curve_name, (int arg0), (arg0)) \
DEFINEFUNC(void, EC_KEY_free, (GO_EC_KEY * arg0), (arg0)) \
DEFINEFUNC(const GO_EC_GROUP *, EC_KEY_get0_group, (const GO_EC_KEY *arg0), (arg0)) \
DEFINEFUNC(int, EC_KEY_generate_key, (GO_EC_KEY * arg0), (arg0)) \
DEFINEFUNC(int, EC_KEY_set_private_key, (GO_EC_KEY * arg0, const GO_BIGNUM *arg1), (arg0, arg1)) \
DEFINEFUNC(int, EC_KEY_set_public_key, (GO_EC_KEY * arg0, const GO_EC_POINT *arg1), (arg0, arg1)) \
DEFINEFUNC(const GO_BIGNUM *, EC_KEY_get0_private_key, (const GO_EC_KEY *arg0), (arg0)) \
DEFINEFUNC(const GO_EC_POINT *, EC_KEY_get0_public_key, (const GO_EC_KEY *arg0), (arg0)) \
DEFINEFUNC(int, ECDSA_do_verify, (const uint8_t *arg0, size_t arg1, const GO_ECDSA_SIG *arg2, const GO_EC_KEY *arg3), (arg0, arg1, arg2, arg3)) \
DEFINEFUNC(size_t, ECDSA_size, (const GO_EC_KEY *arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, ECDSA_sign,  \
    (int type, const unsigned char *dgst, size_t dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey), \
    (type, dgst, dgstlen, sig, siglen, eckey)) \
DEFINEFUNCINTERNAL(int, ECDSA_verify,  \
    (int type, const unsigned char *dgst, size_t dgstlen, const unsigned char *sig, unsigned int siglen, EC_KEY *eckey), \
    (type, dgst, dgstlen, sig, siglen, eckey)) \
DEFINEFUNC_RENAMED(EVP_MD_CTX*, EVP_MD_CTX_new, EVP_MD_CTX_create, (void), ()) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_assign, (EVP_PKEY *pkey, int type, void *eckey), (pkey, type, eckey)) \
DEFINEFUNCINTERNAL(int, EVP_DigestSignInit, \
    (EVP_MD_CTX* ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, const EVP_PKEY *pkey), \
    (ctx, pctx, type, e, pkey)) \
DEFINEFUNCINTERNAL(int, EVP_DigestUpdate, (EVP_MD_CTX* ctx, const void *d, size_t cnt), (ctx, d, cnt)) \
DEFINEFUNCINTERNAL(int, EVP_DigestSignFinal, \
    (EVP_MD_CTX* ctx, unsigned char *sig, unsigned int *siglen), \
    (ctx, sig, siglen)) \
DEFINEFUNCINTERNAL(int, EVP_DigestVerifyInit, \
    (EVP_MD_CTX* ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, const EVP_PKEY *pkey), \
    (ctx, pctx, type, e, pkey)) \
DEFINEFUNCINTERNAL(int, EVP_DigestVerifyFinal, (EVP_MD_CTX* ctx, const uint8_t *sig, unsigned int siglen), (ctx, sig, siglen)) \
DEFINEFUNC_RENAMED(void, EVP_MD_CTX_free, EVP_MD_CTX_destroy, (EVP_MD_CTX *ctx), (ctx)) \
DEFINEFUNC(GO_RSA *, RSA_new, (void), ()) \
DEFINEFUNC(void, RSA_free, (GO_RSA * arg0), (arg0)) \
DEFINEFUNC(int, RSA_sign, \
    (int arg0, const uint8_t *arg1, unsigned int arg2, uint8_t *arg3, unsigned int *arg4, GO_RSA *arg5), \
    (arg0, arg1, arg2, arg3, arg4, arg5)) \
DEFINEFUNC(int, RSA_verify, \
    (int arg0, const uint8_t *arg1, unsigned int arg2, const uint8_t *arg3, unsigned int arg4, GO_RSA *arg5), \
    (arg0, arg1, arg2, arg3, arg4, arg5)) \
DEFINEFUNCINTERNAL(int, RSA_generate_key_ex, \
    (GO_RSA * arg0, int arg1, GO_BIGNUM *arg2, GO_BN_GENCB *arg3), \
    (arg0, arg1, arg2, arg3)) \
DEFINEFUNC_110(int, RSA_set0_factors, (GO_RSA * rsa, GO_BIGNUM *p, GO_BIGNUM *q), (rsa, p, q)) \
DEFINEFUNC_110(int, RSA_set0_crt_params, \
    (GO_RSA * rsa, GO_BIGNUM *dmp1, GO_BIGNUM *dmp2, GO_BIGNUM *iqmp), \
    (rsa, dmp1, dmp2, iqmp)) \
DEFINEFUNC_110(void, RSA_get0_crt_params, \
    (const GO_RSA *r, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmq1, const GO_BIGNUM **iqmp), \
    (r, dmp1, dmq1, iqmp)) \
DEFINEFUNC_110(int, RSA_set0_key, (GO_RSA * r, GO_BIGNUM *n, GO_BIGNUM *e, GO_BIGNUM *d), (r, n, e, d)) \
DEFINEFUNC_110(void, RSA_get0_factors, (const GO_RSA *rsa, const GO_BIGNUM **p, const GO_BIGNUM **q), (rsa, p, q)) \
DEFINEFUNC_110(void, RSA_get0_key, \
    (const GO_RSA *rsa, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d), \
    (rsa, n, e, d)) \
DEFINEFUNC(unsigned int, RSA_size, (const GO_RSA *arg0), (arg0)) \
DEFINEFUNC(int, EVP_EncryptInit_ex, \
    (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv), \
    (ctx, type, impl, key, iv)) \
DEFINEFUNCINTERNAL(int, EVP_EncryptUpdate, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), \
    (ctx, out, outl, in, inl)) \
DEFINEFUNCINTERNAL(int, EVP_EncryptFinal_ex, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl), \
    (ctx, out, outl)) \
DEFINEFUNCINTERNAL(int, EVP_DecryptInit_ex, \
    (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv), \
    (ctx, type, impl, key, iv)) \
DEFINEFUNCINTERNAL(int, EVP_DecryptUpdate, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),	(ctx, out, outl, in, inl)) \
DEFINEFUNCINTERNAL(int, EVP_DecryptFinal_ex, (EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl),	(ctx, outm, outl)) \
DEFINEFUNCINTERNAL(const EVP_CIPHER*, EVP_aes_128_gcm, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ecb, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ecb, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ecb, (void), ()) \
DEFINEFUNCINTERNAL(const EVP_CIPHER*, EVP_aes_256_gcm, (void), ()) \
DEFINEFUNC(void, EVP_CIPHER_CTX_free, (EVP_CIPHER_CTX* arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, EVP_CIPHER_CTX_ctrl, (EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr), (ctx, type, arg, ptr)) \
DEFINEFUNC(GO_EVP_PKEY *, EVP_PKEY_new, (void), ()) \
DEFINEFUNC(void, EVP_PKEY_free, (GO_EVP_PKEY * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_set1_RSA, (GO_EVP_PKEY * arg0, GO_RSA *arg1), (arg0, arg1)) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_verify, \
    (EVP_PKEY_CTX *ctx, const unsigned char *sig, unsigned int siglen, const unsigned char *tbs, size_t tbslen), \
    (ctx, sig, siglen, tbs, tbslen)) \
DEFINEFUNC(GO_EVP_PKEY_CTX *, EVP_PKEY_CTX_new, (GO_EVP_PKEY * arg0, ENGINE *arg1), (arg0, arg1)) \
DEFINEFUNC(void, EVP_PKEY_CTX_free, (GO_EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_CTX_ctrl, \
    (EVP_PKEY_CTX * ctx, int keytype, int optype, int cmd, int p1, void *p2), \
    (ctx, keytype, optype, cmd, p1, p2)) \
DEFINEFUNC_110(int, RSA_pkey_ctx_ctrl, \
    (EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2), \
    (ctx, optype, cmd, p1, p2)) \
DEFINEFUNC(int, EVP_PKEY_decrypt, \
    (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4), \
    (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_encrypt, \
    (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4), \
    (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_decrypt_init, (GO_EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_encrypt_init, (GO_EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_sign_init, (GO_EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_verify_init, (GO_EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNCINTERNAL(int, EVP_PKEY_sign, \
    (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, size_t *arg2, const uint8_t *arg3, size_t arg4), \
    (arg0, arg1, arg2, arg3, arg4))
