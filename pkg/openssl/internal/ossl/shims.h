// This header file is used by the mkcgo tool to generate cgo and Go bindings for the
// OpenSSL C API. Run "go generate ." to regenerate the bindings.
// Do not include this file, import "zossl.h" instead.

#ifndef _GO_OSSL_SHIMS_H // only include this header once
#define _GO_OSSL_SHIMS_H

#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

// The following includes are used by the checkheader tool.
// #include <openssl/crypto.h>
// #include <openssl/evp.h>
// #include <openssl/ec.h>
// #include <openssl/kdf.h>
// #include <openssl/obj_mac.h>
// #include <openssl/rsa.h>
// #include <openssl/err.h>
// #include <openssl/hmac.h>
// #include <openssl/rand.h>
// #include <openssl/dsa.h>
// #if OPENSSL_VERSION_NUMBER >= 0x30000000L
// #include <openssl/core_names.h>
// #include <openssl/provider.h>
// #include <openssl/param_build.h>
// #include <openssl/params.h>
// #endif
// #if OPENSSL_VERSION_NUMBER < 0x10100000L
// #include <openssl/bn.h>
// #endif

enum {
	_POINT_CONVERSION_UNCOMPRESSED = 4,

	_OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002,
	_OPENSSL_INIT_ADD_ALL_CIPHERS     = 0x00000004,
	_OPENSSL_INIT_ADD_ALL_DIGESTS     = 0x00000008,
	_OPENSSL_INIT_LOAD_CONFIG         = 0x00000040,

	_EVP_CTRL_GCM_GET_TAG = 0x10,
	_EVP_CTRL_GCM_SET_TAG = 0x11,
	_EVP_PKEY_CTRL_MD     = 1,
	_EVP_PKEY_RSA         = 6,
	_EVP_PKEY_EC          = 408,
	_EVP_PKEY_TLS1_PRF    = 1021,
	_EVP_PKEY_HKDF        = 1036,
	_EVP_PKEY_ED25519     = 1087,
	_EVP_PKEY_DSA         = 116,
	_EVP_PKEY_OP_DERIVE = (1 << 10), // this value differs between OpenSSL 1 and 3, but we only use it in 1
	_EVP_MAX_MD_SIZE    = 64,

	_EVP_PKEY_PUBLIC_KEY = 0x86,
	_EVP_PKEY_KEYPAIR    = 0x87,

	_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = 0x1001,

	_EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1,
	_EVP_KDF_HKDF_MODE_EXPAND_ONLY  = 2,

	_EVP_PKEY_CTRL_TLS_MD     = 0x1000,
	_EVP_PKEY_CTRL_TLS_SECRET = 0x1001,
	_EVP_PKEY_CTRL_TLS_SEED   = 0x1002,
	_EVP_PKEY_CTRL_HKDF_MD    = 0x1003,
	_EVP_PKEY_CTRL_HKDF_SALT  = 0x1004,
	_EVP_PKEY_CTRL_HKDF_KEY   = 0x1005,
	_EVP_PKEY_CTRL_HKDF_INFO  = 0x1006,
	_EVP_PKEY_CTRL_HKDF_MODE  = 0x1007,

	_NID_X9_62_prime256v1 = 415,
	_NID_secp224r1        = 713,
	_NID_secp384r1        = 715,
	_NID_secp521r1        = 716,

	_RSA_PKCS1_PADDING                 = 1,
	_RSA_NO_PADDING                    = 3,
	_RSA_PKCS1_OAEP_PADDING            = 4,
	_RSA_PKCS1_PSS_PADDING             = 6,
	_RSA_PSS_SALTLEN_DIGEST            = -1,
	_RSA_PSS_SALTLEN_AUTO              = -2,
	_RSA_PSS_SALTLEN_MAX_SIGN          = -2,
	_RSA_PSS_SALTLEN_MAX               = -3,
	_EVP_PKEY_CTRL_RSA_PADDING         = 0x1001,
	_EVP_PKEY_CTRL_RSA_PSS_SALTLEN     = 0x1002,
	_EVP_PKEY_CTRL_RSA_KEYGEN_BITS     = 0x1003,
	_EVP_PKEY_CTRL_RSA_MGF1_MD         = 0x1005,
	_EVP_PKEY_CTRL_RSA_OAEP_MD         = 0x1009,
	_EVP_PKEY_CTRL_RSA_OAEP_LABEL      = 0x100A,
	_EVP_PKEY_CTRL_DSA_PARAMGEN_BITS   = 0x1001,
	_EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = 0x1002,

	_OSSL_PARAM_INTEGER = 1,
	_OSSL_PARAM_OCTET_STRING = 5,
};

typedef void* _OPENSSL_INIT_SETTINGS_PTR;
typedef void* _OSSL_LIB_CTX_PTR;
typedef void* _OSSL_PROVIDER_PTR;
typedef void* _ENGINE_PTR;
typedef void* _EVP_PKEY_PTR;
typedef void* _EVP_PKEY_CTX_PTR;
typedef void* _EVP_MD_PTR;
typedef void* _EVP_MD_CTX_PTR;
typedef void* _HMAC_CTX_PTR;
typedef void* _EVP_CIPHER_PTR;
typedef void* _EVP_CIPHER_CTX_PTR;
typedef void* _EC_KEY_PTR;
typedef void* _EC_POINT_PTR;
typedef void* _EC_GROUP_PTR;
typedef void* _RSA_PTR;
typedef void* _BIGNUM_PTR;
typedef void* _BN_CTX_PTR;
typedef void* _EVP_MAC_PTR;
typedef void* _EVP_MAC_CTX_PTR;
typedef void* _OSSL_PARAM_BLD_PTR;
typedef void* _OSSL_PARAM_PTR;
typedef void* _EVP_SIGNATURE_PTR;
typedef void* _DSA_PTR;
typedef void* _EVP_KDF_PTR;
typedef void* _EVP_KDF_CTX_PTR;
typedef int point_conversion_form_t;

// Tags used by mkcgo to determine which OpenSSL version each function is available in:
// - no tag: OpenSSL 1.0 or later
// - legacy_1: Only OpenSSL 1
// - 3: OpenSSL 3.0 or later
// - 111: OpenSSL 1.1.1 or later

// The noescape/nocallback attributes are performance optimizations.
// Only add functions that have been observed to benefit from these
// directives, not every function that is merely expected to meet
// the noescape/nocallback criteria.

// ERR API
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
void ERR_clear_error(void) __attribute__((tag(""),tag("init_3")));
unsigned long ERR_get_error_line(const char **file, int *line) __attribute__((tag("legacy_1"),noerror));
unsigned long ERR_get_error_all(const char **file, int *line, const char **func, const char **data, int *flags) __attribute__((tag("3"),noerror));

// OPENSSL API
const char *OpenSSL_version(int type) __attribute__((noerror));
void OPENSSL_init(void);
int OPENSSL_init_crypto(uint64_t ops, const _OPENSSL_INIT_SETTINGS_PTR settings);
unsigned long OpenSSL_version_num(void) __attribute__((tag("version"),optional,noerror));
unsigned int OPENSSL_version_major(void) __attribute__((tag("version"),optional,noerror));
unsigned int OPENSSL_version_minor(void) __attribute__((tag("version"),optional,noerror));
unsigned int OPENSSL_version_patch(void) __attribute__((tag("version"),optional,noerror));

// CRYPTO API
void *CRYPTO_malloc(size_t num, const char *file, int line);
void CRYPTO_free(void *str, const char *file, int line);

// FIPS API
int FIPS_mode(void) __attribute__((tag("legacy_1"),tag("init_1"),noerror));
int FIPS_mode_set(int r) __attribute__((tag("legacy_1"),tag("init_1")));

// EVP Config API
int EVP_default_properties_is_fips_enabled(_OSSL_LIB_CTX_PTR libctx) __attribute__((tag("3"),tag("init_3"),noerror));
int EVP_default_properties_enable_fips(_OSSL_LIB_CTX_PTR libctx, int enable) __attribute__((tag("3")));

// OSSL_PROVIDER API
int OSSL_PROVIDER_available(_OSSL_LIB_CTX_PTR libctx, const char *name) __attribute__((tag("3"),noerror));
_OSSL_PROVIDER_PTR OSSL_PROVIDER_try_load(_OSSL_LIB_CTX_PTR libctx, const char *name, int retain_fallbacks) __attribute__((tag("3")));
const char *OSSL_PROVIDER_get0_name(const _OSSL_PROVIDER_PTR prov) __attribute__((tag("3"),noerror));

// RAND API
int RAND_bytes(unsigned char *arg0, int arg1) __attribute__((noescape,nocallback));

// EVP_MD API
_EVP_MD_PTR EVP_MD_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties) __attribute__((tag("3"),tag("init_3")));
void EVP_MD_free(_EVP_MD_PTR md) __attribute__((tag("3"),tag("init_3")));
const char *EVP_MD_get0_name(const _EVP_MD_PTR md) __attribute__((tag("3"),noerror));
int EVP_MD_get_type(const _EVP_MD_PTR md) __attribute__((tag("3"),noerror));
const _OSSL_PROVIDER_PTR EVP_MD_get0_provider(const _EVP_MD_PTR md) __attribute__((tag("3"),tag("init_3"),noerror));
int EVP_MD_get_size(const _EVP_MD_PTR md) __attribute__((tag("3"),tag("legacy_1","EVP_MD_size"),noerror));
int EVP_MD_get_block_size(const _EVP_MD_PTR md) __attribute__((tag("3"),tag("legacy_1","EVP_MD_block_size"),noerror));
const _EVP_MD_PTR EVP_md5_sha1(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_ripemd160(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_md4(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_md5(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha1(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha224(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha256(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha384(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha512(void) __attribute__((noerror));
const _EVP_MD_PTR EVP_sha512_224(void) __attribute__((tag("111"),noerror));
const _EVP_MD_PTR EVP_sha512_256(void) __attribute__((tag("111"),noerror));
const _EVP_MD_PTR EVP_sha3_224(void) __attribute__((tag("111"),noerror));
const _EVP_MD_PTR EVP_sha3_256(void) __attribute__((tag("111"),noerror));
const _EVP_MD_PTR EVP_sha3_384(void) __attribute__((tag("111"),noerror));
const _EVP_MD_PTR EVP_sha3_512(void) __attribute__((tag("111"),noerror));

_EVP_MD_CTX_PTR EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(_EVP_MD_CTX_PTR ctx);
int EVP_MD_CTX_copy(_EVP_MD_CTX_PTR out, const _EVP_MD_CTX_PTR in) __attribute__((noescape,nocallback));
int EVP_MD_CTX_copy_ex(_EVP_MD_CTX_PTR out, const _EVP_MD_CTX_PTR in);
const _OSSL_PARAM_PTR EVP_MD_CTX_gettable_params(_EVP_MD_CTX_PTR ctx) __attribute__((tag("3")));
const _OSSL_PARAM_PTR EVP_MD_CTX_settable_params(_EVP_MD_CTX_PTR ctx) __attribute__((tag("3")));
int EVP_MD_CTX_get_params(_EVP_MD_CTX_PTR ctx, _OSSL_PARAM_PTR params) __attribute__((tag("3")));
int EVP_MD_CTX_set_params(_EVP_MD_CTX_PTR ctx, const _OSSL_PARAM_PTR params) __attribute__((tag("3")));
int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const _EVP_MD_PTR type, _ENGINE_PTR impl) __attribute__((noescape,nocallback,nocheckptr("data")));
int EVP_DigestInit_ex(_EVP_MD_CTX_PTR ctx, const _EVP_MD_PTR type, _ENGINE_PTR impl);
int EVP_DigestInit(_EVP_MD_CTX_PTR ctx, const _EVP_MD_PTR type);
int EVP_DigestUpdate(_EVP_MD_CTX_PTR ctx, const void *d, size_t cnt) __attribute__((noescape,nocallback,nocheckptr("d")));
int EVP_DigestFinal_ex(_EVP_MD_CTX_PTR ctx, unsigned char *md, unsigned int *s) __attribute__((noescape,nocallback));
int EVP_DigestSign(_EVP_MD_CTX_PTR ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen) __attribute__((tag("111"),noescape,nocallback));
int EVP_DigestSignInit(_EVP_MD_CTX_PTR ctx, _EVP_PKEY_CTX_PTR *pctx, const _EVP_MD_PTR type, _ENGINE_PTR e, _EVP_PKEY_PTR pkey);
int EVP_DigestSignFinal(_EVP_MD_CTX_PTR ctx, unsigned char *sig, size_t *siglen);
int EVP_DigestVerifyInit(_EVP_MD_CTX_PTR ctx, _EVP_PKEY_CTX_PTR *pctx, const _EVP_MD_PTR type, _ENGINE_PTR e, _EVP_PKEY_PTR pkey);
int EVP_DigestVerifyFinal(_EVP_MD_CTX_PTR ctx, const unsigned char *sig, size_t siglen);
int EVP_DigestVerify(_EVP_MD_CTX_PTR ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen) __attribute__((tag("111")));

// HMAC API
int HMAC_Init_ex(_HMAC_CTX_PTR arg0, const void *arg1, int arg2, const _EVP_MD_PTR arg3, _ENGINE_PTR arg4) __attribute__((tag("legacy_1")));
int HMAC_Update(_HMAC_CTX_PTR arg0, const unsigned char *arg1, size_t arg2) __attribute__((tag("legacy_1")));
int HMAC_Final(_HMAC_CTX_PTR arg0, unsigned char *arg1, unsigned int *arg2) __attribute__((tag("legacy_1")));

_HMAC_CTX_PTR HMAC_CTX_new(void) __attribute__((tag("legacy_1")));
int HMAC_CTX_copy(_HMAC_CTX_PTR dest, _HMAC_CTX_PTR src) __attribute__((tag("legacy_1")));
void HMAC_CTX_free(_HMAC_CTX_PTR arg0) __attribute__((tag("legacy_1")));

// EVP_CIPHER API
_EVP_CIPHER_PTR EVP_CIPHER_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties) __attribute__((tag("3")));
const char *EVP_CIPHER_get0_name(const _EVP_CIPHER_PTR cipher) __attribute__((tag("3"),noerror));
const _EVP_CIPHER_PTR EVP_aes_128_gcm(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_128_cbc(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_128_ctr(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_128_ecb(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_192_gcm(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_192_cbc(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_192_ctr(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_192_ecb(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_256_cbc(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_256_ctr(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_256_ecb(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_aes_256_gcm(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_des_ecb(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_des_cbc(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_des_ede3_ecb(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_des_ede3_cbc(void) __attribute__((noerror));
const _EVP_CIPHER_PTR EVP_rc4(void) __attribute__((noerror));
int EVP_CIPHER_get_block_size(const _EVP_CIPHER_PTR cipher) __attribute__((tag("3"),tag("legacy_1","EVP_CIPHER_block_size"),noerror));

_EVP_CIPHER_CTX_PTR EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_set_padding(_EVP_CIPHER_CTX_PTR x, int padding);
int EVP_CIPHER_CTX_set_key_length(_EVP_CIPHER_CTX_PTR x, int keylen);
void EVP_CIPHER_CTX_free(_EVP_CIPHER_CTX_PTR arg0);
int EVP_CIPHER_CTX_ctrl(_EVP_CIPHER_CTX_PTR ctx, int type, int arg, void *ptr);
int EVP_CipherInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv, int enc);
int EVP_CipherUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) __attribute__((noescape,nocallback));
int EVP_EncryptInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) __attribute__((noescape,nocallback));
int EVP_EncryptFinal_ex(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl) __attribute__((noescape,nocallback));
int EVP_DecryptInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) __attribute__((noescape,nocallback));
int EVP_DecryptFinal_ex(_EVP_CIPHER_CTX_PTR ctx, unsigned char *outm, int *outl) __attribute__((noescape,nocallback));

// EVP_PKEY API
_EVP_PKEY_PTR EVP_PKEY_new(void);
_EVP_PKEY_PTR EVP_PKEY_new_raw_private_key(int type, _ENGINE_PTR e, const unsigned char *key, size_t keylen) __attribute__((tag("111")));
_EVP_PKEY_PTR EVP_PKEY_new_raw_public_key(int type, _ENGINE_PTR e, const unsigned char *key, size_t keylen) __attribute__((tag("111")));
int EVP_PKEY_get_size(const _EVP_PKEY_PTR pkey) __attribute__((tag("3"),tag("legacy_1","EVP_PKEY_size")));
int EVP_PKEY_get_bits(const _EVP_PKEY_PTR pkey) __attribute__((tag("3"),tag("legacy_1","EVP_PKEY_bits"))); 
void EVP_PKEY_free(_EVP_PKEY_PTR arg0);
_RSA_PTR EVP_PKEY_get1_RSA(_EVP_PKEY_PTR pkey) __attribute__((tag("legacy_1")));
int EVP_PKEY_assign(_EVP_PKEY_PTR pkey, int type, void *key) __attribute__((tag("legacy_1")));
_EC_KEY_PTR EVP_PKEY_get0_EC_KEY(_EVP_PKEY_PTR pkey) __attribute__((tag("legacy_1")));
_DSA_PTR EVP_PKEY_get0_DSA(_EVP_PKEY_PTR pkey) __attribute__((tag("legacy_1")));
int EVP_PKEY_set1_encoded_public_key(_EVP_PKEY_PTR pkey, const unsigned char *pub, size_t publen) __attribute__((tag("3")));
size_t EVP_PKEY_get1_encoded_public_key(_EVP_PKEY_PTR pkey, unsigned char **ppub) __attribute__((tag("3")));
int EVP_PKEY_get_bn_param(const _EVP_PKEY_PTR pkey, const char *key_name, _BIGNUM_PTR *bn) __attribute__((tag("3")));
int EVP_PKEY_up_ref(_EVP_PKEY_PTR key) __attribute__((tag("3")));
int EVP_PKEY_set1_EC_KEY(_EVP_PKEY_PTR pkey, _EC_KEY_PTR key) __attribute__((tag("legacy_1")));
int EVP_PKEY_CTX_set0_rsa_oaep_label(_EVP_PKEY_CTX_PTR ctx, void *label, int len) __attribute__((tag("3")));
int EVP_PKEY_get_raw_public_key(const _EVP_PKEY_PTR pkey, unsigned char *pub, size_t *len) __attribute__((tag("111"),noescape,nocallback));
int EVP_PKEY_get_raw_private_key(const _EVP_PKEY_PTR pkey, unsigned char *priv, size_t *len) __attribute__((tag("111"),noescape,nocallback));
int EVP_PKEY_fromdata_init(_EVP_PKEY_CTX_PTR ctx) __attribute__((tag("3")));
int EVP_PKEY_fromdata(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *pkey, int selection, _OSSL_PARAM_PTR params) __attribute__((tag("3")));
int EVP_PKEY_paramgen_init(_EVP_PKEY_CTX_PTR ctx);
int EVP_PKEY_paramgen(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *ppkey);
int EVP_PKEY_keygen_init(_EVP_PKEY_CTX_PTR ctx);
int EVP_PKEY_keygen(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *ppkey);
int EVP_PKEY_decrypt(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
int EVP_PKEY_encrypt(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
int EVP_PKEY_decrypt_init(_EVP_PKEY_CTX_PTR arg0);
int EVP_PKEY_encrypt_init(_EVP_PKEY_CTX_PTR arg0);
int EVP_PKEY_sign_init(_EVP_PKEY_CTX_PTR arg0);
int EVP_PKEY_verify_init(_EVP_PKEY_CTX_PTR arg0);
int EVP_PKEY_sign(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
int EVP_PKEY_verify(_EVP_PKEY_CTX_PTR ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_derive_init(_EVP_PKEY_CTX_PTR ctx);
int EVP_PKEY_derive_set_peer(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR peer);
int EVP_PKEY_derive(_EVP_PKEY_CTX_PTR ctx, unsigned char *key, size_t *keylen) __attribute__((noescape,nocallback));
int EVP_PKEY_public_check_quick(_EVP_PKEY_CTX_PTR ctx) __attribute__((tag("3")));
int EVP_PKEY_private_check(_EVP_PKEY_CTX_PTR ctx) __attribute__((tag("3")));
_EVP_PKEY_PTR EVP_PKEY_Q_keygen(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type, ...) __attribute__((tag("3")));
_EVP_PKEY_PTR EVP_PKEY_Q_keygen_RSA(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type, size_t arg1) __attribute__((tag("3"),variadic("EVP_PKEY_Q_keygen")));
_EVP_PKEY_PTR EVP_PKEY_Q_keygen_EC(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type, const char *arg1) __attribute__((tag("3"),variadic("EVP_PKEY_Q_keygen")));
_EVP_PKEY_PTR EVP_PKEY_Q_keygen_ED25519(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type) __attribute__((tag("3"),variadic("EVP_PKEY_Q_keygen")));

_EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new(_EVP_PKEY_PTR arg0, _ENGINE_PTR arg1);
_EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_id(int id, _ENGINE_PTR e);
_EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_from_pkey(_OSSL_LIB_CTX_PTR libctx, _EVP_PKEY_PTR pkey, const char *propquery) __attribute__((tag("3")));
void EVP_PKEY_CTX_free(_EVP_PKEY_CTX_PTR arg0);
int EVP_PKEY_CTX_ctrl(_EVP_PKEY_CTX_PTR ctx, int keytype, int optype, int cmd, int p1, void *p2);
int EVP_PKEY_CTX_set_hkdf_mode(_EVP_PKEY_CTX_PTR arg0, int arg1) __attribute__((tag("3")));
int EVP_PKEY_CTX_set_hkdf_md(_EVP_PKEY_CTX_PTR arg0, const _EVP_MD_PTR arg1) __attribute__((tag("3")));
int EVP_PKEY_CTX_set1_hkdf_salt(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2) __attribute__((tag("3")));
int EVP_PKEY_CTX_set1_hkdf_key(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2) __attribute__((tag("3")));
int EVP_PKEY_CTX_add1_hkdf_info(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2) __attribute__((tag("3")));

// RSA API
_RSA_PTR RSA_new(void) __attribute__((tag("legacy_1")));
void RSA_free(_RSA_PTR arg0) __attribute__((tag("legacy_1")));
void RSA_get0_factors(const _RSA_PTR rsa, const _BIGNUM_PTR *p, const _BIGNUM_PTR *q) __attribute__((tag("legacy_1"),noerror));
int RSA_set0_factors(_RSA_PTR rsa, _BIGNUM_PTR p, _BIGNUM_PTR q) __attribute__((tag("legacy_1")));
void RSA_get0_crt_params(const _RSA_PTR r, const _BIGNUM_PTR *dmp1, const _BIGNUM_PTR *dmq1, const _BIGNUM_PTR *iqmp) __attribute__((tag("legacy_1"),noerror));
int RSA_set0_crt_params(_RSA_PTR rsa, _BIGNUM_PTR dmp1, _BIGNUM_PTR dmp2, _BIGNUM_PTR iqmp) __attribute__((tag("legacy_1")));
void RSA_get0_key(const _RSA_PTR rsa, const _BIGNUM_PTR *n, const _BIGNUM_PTR *e, const _BIGNUM_PTR *d) __attribute__((tag("legacy_1"),noerror));
int RSA_set0_key(_RSA_PTR r, _BIGNUM_PTR n, _BIGNUM_PTR e, _BIGNUM_PTR d) __attribute__((tag("legacy_1")));

// BIGNUM API
_BIGNUM_PTR BN_new(void);
void BN_free(_BIGNUM_PTR arg0);
void BN_clear(_BIGNUM_PTR arg0);
void BN_clear_free(_BIGNUM_PTR arg0);
int BN_num_bits(const _BIGNUM_PTR arg0) __attribute__((noerror));
_BIGNUM_PTR BN_bin2bn(const unsigned char *arg0, int arg1, _BIGNUM_PTR arg2);
_BIGNUM_PTR BN_lebin2bn(const unsigned char *s, int len, _BIGNUM_PTR ret);
int BN_bn2lebinpad(const _BIGNUM_PTR a, unsigned char *to, int tolen) __attribute__((errcond("== -1")));
int BN_bn2binpad(const _BIGNUM_PTR a, unsigned char *to, int tolen) __attribute__((errcond("== -1")));

// EC API
int EC_KEY_set_public_key_affine_coordinates(_EC_KEY_PTR key, _BIGNUM_PTR x, _BIGNUM_PTR y) __attribute__((tag("legacy_1")));
int EC_KEY_set_public_key(_EC_KEY_PTR key, const _EC_POINT_PTR pub) __attribute__((tag("legacy_1")));
void EC_KEY_free(_EC_KEY_PTR arg0) __attribute__((tag("legacy_1")));
const _EC_GROUP_PTR EC_KEY_get0_group(const _EC_KEY_PTR arg0) __attribute__((tag("legacy_1"),noerror));
const _BIGNUM_PTR EC_KEY_get0_private_key(const _EC_KEY_PTR arg0) __attribute__((tag("legacy_1"),noerror));
const _EC_POINT_PTR EC_KEY_get0_public_key(const _EC_KEY_PTR arg0) __attribute__((tag("legacy_1"),noerror));
_EC_KEY_PTR EC_KEY_new_by_curve_name(int arg0) __attribute__((tag("legacy_1")));
int EC_KEY_set_private_key(_EC_KEY_PTR arg0, const _BIGNUM_PTR arg1) __attribute__((tag("legacy_1")));
int EC_KEY_check_key(const _EC_KEY_PTR key) __attribute__((tag("legacy_1")));
_EC_POINT_PTR EC_POINT_new(const _EC_GROUP_PTR arg0);
void EC_POINT_free(_EC_POINT_PTR arg0);
int EC_POINT_mul(const _EC_GROUP_PTR group, _EC_POINT_PTR r, const _BIGNUM_PTR n, const _EC_POINT_PTR q, const _BIGNUM_PTR m, _BN_CTX_PTR ctx);
int EC_POINT_get_affine_coordinates_GFp(const _EC_GROUP_PTR arg0, const _EC_POINT_PTR arg1, _BIGNUM_PTR arg2, _BIGNUM_PTR arg3, _BN_CTX_PTR arg4) __attribute__((tag("legacy_1")));
int EC_POINT_set_affine_coordinates(const _EC_GROUP_PTR arg0, _EC_POINT_PTR arg1, const _BIGNUM_PTR arg2, const _BIGNUM_PTR arg3, _BN_CTX_PTR arg4)  __attribute__((tag("3")));
size_t EC_POINT_point2oct(const _EC_GROUP_PTR group, const _EC_POINT_PTR p, point_conversion_form_t form, unsigned char *buf, size_t len, _BN_CTX_PTR ctx);
int EC_POINT_oct2point(const _EC_GROUP_PTR group, _EC_POINT_PTR p, const unsigned char *buf, size_t len, _BN_CTX_PTR ctx);
_EC_GROUP_PTR EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(_EC_GROUP_PTR group);

// EVP_MAC API
_EVP_MAC_PTR EVP_MAC_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties) __attribute__((tag("3")));
_EVP_MAC_CTX_PTR EVP_MAC_CTX_new(_EVP_MAC_PTR arg0) __attribute__((tag("3")));
int EVP_MAC_CTX_set_params(_EVP_MAC_CTX_PTR ctx, const _OSSL_PARAM_PTR params) __attribute__((tag("3")));
void EVP_MAC_CTX_free(_EVP_MAC_CTX_PTR arg0) __attribute__((tag("3")));
_EVP_MAC_CTX_PTR EVP_MAC_CTX_dup(const _EVP_MAC_CTX_PTR arg0) __attribute__((tag("3")));
int EVP_MAC_init(_EVP_MAC_CTX_PTR ctx, const unsigned char *key, size_t keylen, const _OSSL_PARAM_PTR params) __attribute__((tag("3")));
int EVP_MAC_update(_EVP_MAC_CTX_PTR ctx, const unsigned char *data, size_t datalen) __attribute__((tag("3")));
int EVP_MAC_final(_EVP_MAC_CTX_PTR ctx, unsigned char *out, size_t *outl, size_t outsize) __attribute__((tag("3")));

// OSSL_PARAM API
void OSSL_PARAM_free(_OSSL_PARAM_PTR p) __attribute__((tag("3")));
const _OSSL_PARAM_PTR OSSL_PARAM_locate_const(const _OSSL_PARAM_PTR p, const char *key) __attribute__((tag("3")));
_OSSL_PARAM_BLD_PTR OSSL_PARAM_BLD_new(void) __attribute__((tag("3")));
void OSSL_PARAM_BLD_free(_OSSL_PARAM_BLD_PTR bld) __attribute__((tag("3")));
_OSSL_PARAM_PTR OSSL_PARAM_BLD_to_param(_OSSL_PARAM_BLD_PTR bld) __attribute__((tag("3")));
int OSSL_PARAM_BLD_push_utf8_string(_OSSL_PARAM_BLD_PTR bld, const char *key, const char *buf, size_t bsize) __attribute__((tag("3")));
int OSSL_PARAM_BLD_push_octet_string(_OSSL_PARAM_BLD_PTR bld, const char *key, const void *buf, size_t bsize) __attribute__((tag("3")));
int OSSL_PARAM_BLD_push_BN(_OSSL_PARAM_BLD_PTR bld, const char *key, const _BIGNUM_PTR bn) __attribute__((tag("3")));
int OSSL_PARAM_BLD_push_int32(_OSSL_PARAM_BLD_PTR bld, const char *key, int32_t num) __attribute__((tag("3")));

// EVP_SIGNATURE API
_EVP_SIGNATURE_PTR EVP_SIGNATURE_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties) __attribute__((tag("3")));
void EVP_SIGNATURE_free(_EVP_SIGNATURE_PTR signature) __attribute__((tag("3")));

// DSA API
_DSA_PTR DSA_new(void) __attribute__((tag("legacy_1")));
void DSA_free(_DSA_PTR r) __attribute__((tag("legacy_1")));
int DSA_generate_key(_DSA_PTR a) __attribute__((tag("legacy_1")));
void DSA_get0_pqg(const _DSA_PTR d, const _BIGNUM_PTR *p, const _BIGNUM_PTR *q, const _BIGNUM_PTR *g) __attribute__((tag("legacy_1")));
int DSA_set0_pqg(_DSA_PTR d, _BIGNUM_PTR p, _BIGNUM_PTR q, _BIGNUM_PTR g) __attribute__((tag("legacy_1")));
void DSA_get0_key(const _DSA_PTR d, const _BIGNUM_PTR *pub_key, const _BIGNUM_PTR *priv_key) __attribute__((tag("legacy_1")));
int DSA_set0_key(_DSA_PTR d, _BIGNUM_PTR pub_key, _BIGNUM_PTR priv_key) __attribute__((tag("legacy_1")));

// EVP_KDF API
_EVP_KDF_PTR EVP_KDF_fetch(_OSSL_LIB_CTX_PTR libctx, const char *algorithm, const char *properties) __attribute__((tag("3")));
void EVP_KDF_free(_EVP_KDF_PTR kdf) __attribute__((tag("3")));
_EVP_KDF_CTX_PTR EVP_KDF_CTX_new(_EVP_KDF_PTR kdf) __attribute__((tag("3")));
int EVP_KDF_CTX_set_params(_EVP_KDF_CTX_PTR ctx, const _OSSL_PARAM_PTR params) __attribute__((tag("3")));
void EVP_KDF_CTX_free(_EVP_KDF_CTX_PTR ctx) __attribute__((tag("3")));
size_t EVP_KDF_CTX_get_kdf_size(_EVP_KDF_CTX_PTR ctx) __attribute__((tag("3")));
int EVP_KDF_derive(_EVP_KDF_CTX_PTR ctx, unsigned char *key, size_t keylen, const _OSSL_PARAM_PTR params) __attribute__((tag("3")));
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const _EVP_MD_PTR digest, int keylen, unsigned char *out);

// OBJ API
const char *OBJ_nid2sn(int n) __attribute__((noerror));

#endif // _GO_OSSL_SHIMS_H
