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

#include <openssl/ossl_typ.h>

#define unlikely(x) __builtin_expect(!!(x), 0)
#define DEFINEFUNC(ret, func, args, argscall)        \
	typedef ret(*_goboringcrypto_PTR_##func) args;   \
	static _goboringcrypto_PTR_##func _g_##func = 0; \
	static inline ret _goboringcrypto_##func args    \
	{                                                \
		if (unlikely(!_g_##func))                    \
		{                                            \
			_g_##func = dlsym(handle, #func);        \
		}                                            \
		return _g_##func argscall;                   \
	}

#define DEFINEFUNCINTERNAL(ret, func, args, argscall)        \
	typedef ret(*_goboringcrypto_internal_PTR_##func) args;   \
	static _goboringcrypto_internal_PTR_##func _g_internal_##func = 0; \
	static inline ret _goboringcrypto_internal_##func args    \
	{                                                \
		if (unlikely(!_g_internal_##func))                    \
		{                                            \
			_g_internal_##func = dlsym(handle, #func);        \
		}                                            \
		return _g_internal_##func argscall;                   \
	}

#define DEFINEMACRO(ret, func, args, argscall)    \
	static inline ret _goboringcrypto_##func args \
	{                                             \
		return func argscall;                     \
	}

// x.x.x, considering the max number of decimal digits for each component
#define MaxVersionStringLength 32
#define OPENSSL_VERSION_3_0_RTM 0x30000000L
#define OPENSSL_VERSION_1_1_1_RTM 0x10101000L
#define OPENSSL_VERSION_1_1_0_RTM 0x10100000L
#define OPENSSL_VERSION_1_0_2_RTM 0x10002000L
#define SONAME_BASE "libcrypto.so."
#define MAKELIB(v)  SONAME_BASE v

#include <dlfcn.h>

static void* handle = NULL;

static void
_goboringcrypto_DLOPEN(const char* libraryName)
{
	handle = dlopen(libraryName, RTLD_NOW | RTLD_GLOBAL);
}

static void*
_goboringcrypto_DLOPEN_OPENSSL(void)
{
	if (handle)
	{
		return handle;
	}

	// Approach taken from .Net System.Security.Cryptography.Native
	// https://github.com/dotnet/runtime/blob/f64246ce08fb7a58221b2b7c8e68f69c02522b0d/src/libraries/Native/Unix/System.Security.Cryptography.Native/opensslshim.c#L54

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

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_RTM
	if (handle == NULL)
	{
		_goboringcrypto_DLOPEN(MAKELIB("3"));
	}
#elif OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0_RTM
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
#else
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
#endif
	return handle;
}

#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

DEFINEFUNCINTERNAL(void, ERR_print_errors_fp, (FILE* fp), (fp))
DEFINEFUNCINTERNAL(unsigned long, ERR_get_error, (void), ())
DEFINEFUNCINTERNAL(void, ERR_error_string_n, (unsigned long e, unsigned char *buf, size_t len), (e, buf, len))

DEFINEFUNCINTERNAL(int, RAND_poll, (void), ())

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_2_RTM
DEFINEFUNCINTERNAL(void, OPENSSL_init, (void), ())
#endif

#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
int _goboringcrypto_OPENSSL_thread_setup(void);
DEFINEFUNCINTERNAL(void, ERR_load_crypto_strings, (void), ())
DEFINEFUNCINTERNAL(int, CRYPTO_num_locks, (void), ())
DEFINEFUNCINTERNAL(void, CRYPTO_set_id_callback, (unsigned long (*id_function)(void)), (id_function))
DEFINEFUNCINTERNAL(void, CRYPTO_set_locking_callback,
	(void (*locking_function)(int mode, int n, const char *file, int line)), 
	(locking_function))
DEFINEFUNCINTERNAL(void, OPENSSL_add_all_algorithms_conf, (void), ())
#else
DEFINEFUNCINTERNAL(int, OPENSSL_init_crypto, (uint64_t ops, const OPENSSL_INIT_SETTINGS *settings), (ops, settings))
#endif

static int
_goboringcrypto_OPENSSL_setup(void) {
	// OPENSSL_init initialize FIPS callbacks and rand generator.
	// no-op from OpenSSL 1.1.1 onwards.
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_2_RTM
	_goboringcrypto_internal_OPENSSL_init();
#endif
	#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
		if (_goboringcrypto_OPENSSL_thread_setup() != 1)
		{
			return 0;
		}
		// Load all algorithms and the openssl configuration file.
		_goboringcrypto_internal_OPENSSL_add_all_algorithms_conf();

		// Ensure that the error message table is loaded.
		_goboringcrypto_internal_ERR_load_crypto_strings();
		return 1;

	#else
		// In OpenSSL 1.0 we call OPENSSL_add_all_algorithms_conf() and ERR_load_crypto_strings(),
		// so do the same for 1.1
		return _goboringcrypto_internal_OPENSSL_init_crypto(
				OPENSSL_INIT_ADD_ALL_CIPHERS |
				OPENSSL_INIT_ADD_ALL_DIGESTS |
				OPENSSL_INIT_LOAD_CONFIG |
				OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			NULL);
	#endif
}

DEFINEFUNC(int, FIPS_mode, (void), ())
DEFINEFUNC(int, FIPS_mode_set, (int r), (r))

DEFINEFUNC(int, RAND_set_rand_method, (const RAND_METHOD *rand), (rand))
DEFINEFUNC(RAND_METHOD*, RAND_get_rand_method, (void), ())
DEFINEFUNC(int, RAND_bytes, (uint8_t * arg0, size_t arg1), (arg0, arg1))

int _goboringcrypto_stub_openssl_rand(void);
int _goboringcrypto_restore_openssl_rand(void);
int fbytes(unsigned char *buf, int num);


#include <openssl/obj_mac.h>

enum
{
	GO_NID_md5_sha1 = NID_md5_sha1,

	GO_NID_secp224r1 = NID_secp224r1,
	GO_NID_X9_62_prime256v1 = NID_X9_62_prime256v1,
	GO_NID_secp384r1 = NID_secp384r1,
	GO_NID_secp521r1 = NID_secp521r1,

	GO_NID_sha224 = NID_sha224,
	GO_NID_sha256 = NID_sha256,
	GO_NID_sha384 = NID_sha384,
	GO_NID_sha512 = NID_sha512,
};

#include <openssl/sha.h>

typedef SHA_CTX GO_SHA_CTX;

DEFINEFUNC(int, SHA1_Init, (GO_SHA_CTX * arg0), (arg0))
DEFINEFUNC(int, SHA1_Update, (GO_SHA_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, SHA1_Final, (uint8_t * arg0, GO_SHA_CTX *arg1), (arg0, arg1))

typedef SHA256_CTX GO_SHA256_CTX;

DEFINEFUNC(int, SHA224_Init, (GO_SHA256_CTX * arg0), (arg0))
DEFINEFUNC(int, SHA224_Update, (GO_SHA256_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, SHA224_Final, (uint8_t * arg0, GO_SHA256_CTX *arg1), (arg0, arg1))

DEFINEFUNC(int, SHA256_Init, (GO_SHA256_CTX * arg0), (arg0))
DEFINEFUNC(int, SHA256_Update, (GO_SHA256_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, SHA256_Final, (uint8_t * arg0, GO_SHA256_CTX *arg1), (arg0, arg1))

typedef SHA512_CTX GO_SHA512_CTX;
DEFINEFUNC(int, SHA384_Init, (GO_SHA512_CTX * arg0), (arg0))
DEFINEFUNC(int, SHA384_Update, (GO_SHA512_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, SHA384_Final, (uint8_t * arg0, GO_SHA512_CTX *arg1), (arg0, arg1))

DEFINEFUNC(int, SHA512_Init, (GO_SHA512_CTX * arg0), (arg0))
DEFINEFUNC(int, SHA512_Update, (GO_SHA512_CTX * arg0, const void *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, SHA512_Final, (uint8_t * arg0, GO_SHA512_CTX *arg1), (arg0, arg1))

#include <openssl/evp.h>

typedef EVP_MD GO_EVP_MD;
DEFINEFUNC(const GO_EVP_MD *, EVP_md4, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_md5, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha1, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha224, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha256, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha384, (void), ())
DEFINEFUNC(const GO_EVP_MD *, EVP_sha512, (void), ())
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_3_0_RTM
DEFINEFUNCINTERNAL(int, EVP_MD_type, (const GO_EVP_MD *arg0), (arg0))
#else
DEFINEFUNCINTERNAL(int, EVP_MD_get_type, (const GO_EVP_MD *arg0), (arg0))
#endif
DEFINEFUNCINTERNAL(size_t, EVP_MD_size, (const GO_EVP_MD *arg0), (arg0))
DEFINEFUNCINTERNAL(const GO_EVP_MD*, EVP_md5_sha1, (void), ())

# include <openssl/md5.h>
DEFINEFUNCINTERNAL(int, MD5_Init, (MD5_CTX *c), (c))
DEFINEFUNCINTERNAL(int, MD5_Update, (MD5_CTX *c, const void *data, size_t len), (c, data, len))
DEFINEFUNCINTERNAL(int, MD5_Final, (unsigned char *md, MD5_CTX *c), (md, c))

static inline int
_goboringcrypto_EVP_MD_type(const GO_EVP_MD *md) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_3_0_RTM
	return _goboringcrypto_internal_EVP_MD_type(md);
#else
	return _goboringcrypto_internal_EVP_MD_get_type(md);
#endif
}

const GO_EVP_MD* _goboringcrypto_backport_EVP_md5_sha1(void);
static inline const GO_EVP_MD*
_goboringcrypto_EVP_md5_sha1(void) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	return _goboringcrypto_backport_EVP_md5_sha1();
#else
	return _goboringcrypto_internal_EVP_md5_sha1();
#endif
}

#include <openssl/hmac.h>

typedef HMAC_CTX GO_HMAC_CTX;

DEFINEFUNC(void, HMAC_CTX_init, (GO_HMAC_CTX * arg0), (arg0))
DEFINEFUNC(void, HMAC_CTX_cleanup, (GO_HMAC_CTX * arg0), (arg0))
DEFINEFUNC(int, HMAC_Init_ex,
		   (GO_HMAC_CTX * arg0, const void *arg1, int arg2, const GO_EVP_MD *arg3, ENGINE *arg4),
		   (arg0, arg1, arg2, arg3, arg4))
DEFINEFUNC(int, HMAC_Update, (GO_HMAC_CTX * arg0, const uint8_t *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, HMAC_Final, (GO_HMAC_CTX * arg0, uint8_t *arg1, unsigned int *arg2), (arg0, arg1, arg2))
DEFINEFUNC(size_t, HMAC_CTX_copy, (GO_HMAC_CTX *dest, GO_HMAC_CTX *src), (dest, src))

DEFINEFUNCINTERNAL(void, HMAC_CTX_free, (GO_HMAC_CTX * arg0), (arg0))
static inline void
_goboringcrypto_HMAC_CTX_free(HMAC_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
   if (ctx != NULL) {
	   _goboringcrypto_HMAC_CTX_cleanup(ctx);
	   free(ctx);
   }
#else
	_goboringcrypto_internal_HMAC_CTX_free(ctx);
#endif
}

DEFINEFUNCINTERNAL(EVP_MD*, HMAC_CTX_get_md, (const GO_HMAC_CTX* ctx), (ctx))
DEFINEFUNCINTERNAL(size_t, EVP_MD_get_size, (const GO_EVP_MD *arg0), (arg0))
static inline size_t
_goboringcrypto_HMAC_size(const GO_HMAC_CTX* arg0) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	return _goboringcrypto_internal_EVP_MD_size(arg0->md);
#elif OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_RTM
	const EVP_MD* md;
	md = _goboringcrypto_internal_HMAC_CTX_get_md(arg0);
	return _goboringcrypto_internal_EVP_MD_get_size(md);
#else
	const EVP_MD* md;
	md = _goboringcrypto_internal_HMAC_CTX_get_md(arg0);
	return _goboringcrypto_internal_EVP_MD_size(md);
#endif
}

DEFINEFUNCINTERNAL(GO_HMAC_CTX*, HMAC_CTX_new, (void), ())
static inline GO_HMAC_CTX*
_goboringcrypto_HMAC_CTX_new(void) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	GO_HMAC_CTX* ctx = malloc(sizeof(GO_HMAC_CTX));
	if (ctx != NULL)
		_goboringcrypto_HMAC_CTX_init(ctx);
	return ctx;
#else
	return _goboringcrypto_internal_HMAC_CTX_new();
#endif
}

DEFINEFUNCINTERNAL(void, HMAC_CTX_reset, (GO_HMAC_CTX * arg0), (arg0))
static inline void
_goboringcrypto_HMAC_CTX_reset(GO_HMAC_CTX* ctx) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	_goboringcrypto_HMAC_CTX_cleanup(ctx);
	_goboringcrypto_HMAC_CTX_init(ctx);
#else
	_goboringcrypto_internal_HMAC_CTX_reset(ctx);
#endif
}

int _goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX *dest, const GO_HMAC_CTX *src);

#include <openssl/evp.h>
#include <openssl/aes.h>

DEFINEFUNC(EVP_CIPHER_CTX *, EVP_CIPHER_CTX_new, (void), ())
DEFINEFUNC(int, EVP_CIPHER_CTX_set_padding, (EVP_CIPHER_CTX *x, int padding), (x, padding))
DEFINEFUNC(int, EVP_CipherInit_ex,
		   (EVP_CIPHER_CTX * ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc),
		   (ctx, type, impl, key, iv, enc))
DEFINEFUNC(int, EVP_CipherUpdate,
		   (EVP_CIPHER_CTX * ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),
		   (ctx, out, outl, in, inl))

void _goboringcrypto_EVP_AES_ctr128_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

int _goboringcrypto_EVP_AES_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

enum
{
	GO_AES_ENCRYPT = 1,
	GO_AES_DECRYPT = 0
};
void _goboringcrypto_EVP_AES_cbc_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *arg0, uint8_t *arg1, size_t arg2, const uint8_t *a, const int arg5);
DEFINEFUNC(void, AES_cbc_encrypt,
		   (const unsigned char *in, unsigned char *out,
					 size_t length, const AES_KEY *key,
					 unsigned char *ivec, const int enc),
		   (in, out, length, key, ivec, enc))

void EVP_AES_cbc_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

void EVP_AES_cbc_dec(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

typedef ENGINE GO_ENGINE;

#include <openssl/bn.h>

typedef BN_CTX GO_BN_CTX;
typedef BIGNUM GO_BIGNUM;

DEFINEFUNC(GO_BIGNUM *, BN_new, (void), ())
DEFINEFUNC(void, BN_free, (GO_BIGNUM * arg0), (arg0))
DEFINEFUNC(void, BN_clear_free, (GO_BIGNUM * arg0), (arg0))
DEFINEFUNC(int, BN_set_word, (BIGNUM *a, BN_ULONG w), (a, w))
DEFINEFUNC(unsigned int, BN_num_bits, (const GO_BIGNUM *arg0), (arg0))
DEFINEFUNC(int, BN_is_negative, (const GO_BIGNUM *arg0), (arg0))
DEFINEFUNC(GO_BIGNUM *, BN_bin2bn, (const uint8_t *arg0, size_t arg1, GO_BIGNUM *arg2), (arg0, arg1, arg2))
DEFINEFUNC(size_t, BN_bn2bin, (const GO_BIGNUM *arg0, uint8_t *arg1), (arg0, arg1))

static inline unsigned int
_goboringcrypto_BN_num_bytes(const GO_BIGNUM* a) {
	return ((_goboringcrypto_BN_num_bits(a)+7)/8);
}

#include <openssl/ec.h>

typedef EC_GROUP GO_EC_GROUP;

DEFINEFUNC(GO_EC_GROUP *, EC_GROUP_new_by_curve_name, (int arg0), (arg0))
DEFINEFUNC(void, EC_GROUP_free, (GO_EC_GROUP * arg0), (arg0))

typedef EC_POINT GO_EC_POINT;

DEFINEFUNC(GO_EC_POINT *, EC_POINT_new, (const GO_EC_GROUP *arg0), (arg0))
DEFINEFUNC(void, EC_POINT_free, (GO_EC_POINT * arg0), (arg0))
DEFINEFUNC(int, EC_POINT_get_affine_coordinates_GFp,
		   (const GO_EC_GROUP *arg0, const GO_EC_POINT *arg1, GO_BIGNUM *arg2, GO_BIGNUM *arg3, GO_BN_CTX *arg4),
		   (arg0, arg1, arg2, arg3, arg4))
DEFINEFUNC(int, EC_POINT_set_affine_coordinates_GFp,
		   (const GO_EC_GROUP *arg0, GO_EC_POINT *arg1, const GO_BIGNUM *arg2, const GO_BIGNUM *arg3, GO_BN_CTX *arg4),
		   (arg0, arg1, arg2, arg3, arg4))

typedef EC_KEY GO_EC_KEY;

DEFINEFUNC(GO_EC_KEY *, EC_KEY_new, (void), ())
DEFINEFUNC(GO_EC_KEY *, EC_KEY_new_by_curve_name, (int arg0), (arg0))
DEFINEFUNC(void, EC_KEY_free, (GO_EC_KEY * arg0), (arg0))
DEFINEFUNC(const GO_EC_GROUP *, EC_KEY_get0_group, (const GO_EC_KEY *arg0), (arg0))
DEFINEFUNC(int, EC_KEY_generate_key, (GO_EC_KEY * arg0), (arg0))
DEFINEFUNC(int, EC_KEY_set_private_key, (GO_EC_KEY * arg0, const GO_BIGNUM *arg1), (arg0, arg1))
DEFINEFUNC(int, EC_KEY_set_public_key, (GO_EC_KEY * arg0, const GO_EC_POINT *arg1), (arg0, arg1))
DEFINEFUNC(const GO_BIGNUM *, EC_KEY_get0_private_key, (const GO_EC_KEY *arg0), (arg0))
DEFINEFUNC(const GO_EC_POINT *, EC_KEY_get0_public_key, (const GO_EC_KEY *arg0), (arg0))

// TODO: EC_KEY_check_fips?

#include <openssl/ecdsa.h>

typedef ECDSA_SIG GO_ECDSA_SIG;

DEFINEFUNC(GO_ECDSA_SIG *, ECDSA_SIG_new, (void), ())
DEFINEFUNC(void, ECDSA_SIG_free, (GO_ECDSA_SIG * arg0), (arg0))
DEFINEFUNC(GO_ECDSA_SIG *, ECDSA_do_sign, (const uint8_t *arg0, size_t arg1, const GO_EC_KEY *arg2), (arg0, arg1, arg2))
DEFINEFUNC(int, ECDSA_do_verify, (const uint8_t *arg0, size_t arg1, const GO_ECDSA_SIG *arg2, const GO_EC_KEY *arg3), (arg0, arg1, arg2, arg3))
DEFINEFUNC(size_t, ECDSA_size, (const GO_EC_KEY *arg0), (arg0))

DEFINEFUNCINTERNAL(int, ECDSA_sign, 
	(int type, const unsigned char *dgst, size_t dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey),
	(type, dgst, dgstlen, sig, siglen, eckey))

DEFINEFUNCINTERNAL(int, ECDSA_verify, 
	(int type, const unsigned char *dgst, size_t dgstlen, const unsigned char *sig, unsigned int siglen, EC_KEY *eckey),
	(type, dgst, dgstlen, sig, siglen, eckey))

DEFINEFUNCINTERNAL(EVP_MD_CTX*, EVP_MD_CTX_new, (void), ())
DEFINEFUNCINTERNAL(EVP_MD_CTX*, EVP_MD_CTX_create, (void), ())

static inline EVP_MD_CTX* _goboringcrypto_EVP_MD_CTX_create(void) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	return _goboringcrypto_internal_EVP_MD_CTX_create();
#else
	return _goboringcrypto_internal_EVP_MD_CTX_new();
#endif
}

DEFINEFUNCINTERNAL(int, EVP_PKEY_assign,
	(EVP_PKEY *pkey, int type, void *eckey),
	(pkey, type, eckey))

static inline int
_goboringcrypto_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, GO_EC_KEY *eckey) {
	return _goboringcrypto_internal_EVP_PKEY_assign(pkey, EVP_PKEY_EC, (char *)(eckey));
}

static inline int
_goboringcrypto_EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *rsa) {
	return _goboringcrypto_internal_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, (char *)(rsa));
}

DEFINEFUNC(int, EVP_DigestSignInit,
	(EVP_MD_CTX* ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, const EVP_PKEY *pkey),
	(ctx, pctx, type, e, pkey))

DEFINEFUNC(int, EVP_DigestUpdate,
	(EVP_MD_CTX* ctx, const void *d, size_t cnt),
	(ctx, d, cnt))
DEFINEFUNC(int, EVP_DigestSignFinal,
	(EVP_MD_CTX* ctx, unsigned char *sig, unsigned int *siglen),
	(ctx, sig, siglen))

DEFINEFUNC(int, EVP_DigestVerifyInit,
	(EVP_MD_CTX* ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, const EVP_PKEY *pkey),
	(ctx, pctx, type, e, pkey))
DEFINEFUNC(int, EVP_DigestVerifyFinal,
	(EVP_MD_CTX* ctx, const uint8_t *sig, unsigned int siglen),
	(ctx, sig, siglen))

int _goboringcrypto_EVP_sign(EVP_MD* md, EVP_PKEY_CTX *ctx, const uint8_t *msg, size_t msgLen, uint8_t *sig, unsigned int *slen, EVP_PKEY *eckey);
int _goboringcrypto_EVP_verify(EVP_MD* md, EVP_PKEY_CTX *ctx, const uint8_t *msg, size_t msgLen, const uint8_t *sig, unsigned int slen, EVP_PKEY *key);

DEFINEFUNCINTERNAL(void, EVP_MD_CTX_free, (EVP_MD_CTX *ctx), (ctx))
DEFINEFUNCINTERNAL(void, EVP_MD_CTX_destroy, (EVP_MD_CTX *ctx), (ctx))
static inline void _goboringcrypto_EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	return _goboringcrypto_internal_EVP_MD_CTX_destroy(ctx);
#else
	return _goboringcrypto_internal_EVP_MD_CTX_free(ctx);
#endif
}

int _goboringcrypto_ECDSA_sign(EVP_MD *md, const uint8_t *arg1, size_t arg2, uint8_t *arg3, unsigned int *arg4, GO_EC_KEY *arg5);
int _goboringcrypto_ECDSA_verify(EVP_MD *md, const uint8_t *arg1, size_t arg2, const uint8_t *arg3, unsigned int arg4, GO_EC_KEY *arg5);

#include <openssl/rsa.h>

// Note: order of struct fields here is unchecked.
typedef RSA GO_RSA;
typedef BN_GENCB GO_BN_GENCB;

int _goboringcrypto_EVP_RSA_sign(EVP_MD* md, const uint8_t *msg, unsigned int msgLen, uint8_t *sig, unsigned int *slen, RSA *rsa);
int _goboringcrypto_EVP_RSA_verify(EVP_MD* md, const uint8_t *msg, unsigned int msgLen, const uint8_t *sig, unsigned int slen, GO_RSA *rsa);

DEFINEFUNC(GO_RSA *, RSA_new, (void), ())
DEFINEFUNC(void, RSA_free, (GO_RSA * arg0), (arg0))
DEFINEFUNC(int, RSA_private_encrypt,
	(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding),
	(flen, from, to, rsa, padding))
DEFINEFUNC(int, RSA_public_decrypt,
	(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding),
	(flen, from, to, rsa, padding))
DEFINEFUNC(int, RSA_sign,
	(int arg0, const uint8_t *arg1, unsigned int arg2, uint8_t *arg3, unsigned int *arg4, GO_RSA *arg5),
	(arg0, arg1, arg2, arg3, arg4, arg5))
DEFINEFUNC(int, RSA_verify,
	(int arg0, const uint8_t *arg1, unsigned int arg2, const uint8_t *arg3, unsigned int arg4, GO_RSA *arg5),
	(arg0, arg1, arg2, arg3, arg4, arg5))
DEFINEFUNC(int, RSA_generate_key_ex,
	(GO_RSA * arg0, int arg1, GO_BIGNUM *arg2, GO_BN_GENCB *arg3),
	(arg0, arg1, arg2, arg3))

DEFINEFUNCINTERNAL(int, RSA_set0_factors,
	(GO_RSA * rsa, GO_BIGNUM *p, GO_BIGNUM *q),
	(rsa, p, q))

static inline int
_goboringcrypto_RSA_set0_factors(GO_RSA * r, GO_BIGNUM *p, GO_BIGNUM *q) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	/* If the fields p and q in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->p == NULL && p == NULL)
		|| (r->q == NULL && q == NULL))
		return 0;

	if (p != NULL) {
		_goboringcrypto_BN_clear_free(r->p);
		r->p = p;
	}
	if (q != NULL) {
		_goboringcrypto_BN_clear_free(r->q);
		r->q = q;
	}

	return 1;
#else
	return _goboringcrypto_internal_RSA_set0_factors(r, p, q);
#endif
}

DEFINEFUNCINTERNAL(int, RSA_set0_crt_params,
		   (GO_RSA * rsa, GO_BIGNUM *dmp1, GO_BIGNUM *dmp2, GO_BIGNUM *iqmp),
		   (rsa, dmp1, dmp2, iqmp))

static inline int
_goboringcrypto_RSA_set0_crt_params(GO_RSA * r, GO_BIGNUM *dmp1, GO_BIGNUM *dmq1, GO_BIGNUM *iqmp) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	/* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->dmp1 == NULL && dmp1 == NULL)
		|| (r->dmq1 == NULL && dmq1 == NULL)
		|| (r->iqmp == NULL && iqmp == NULL))
		return 0;

	if (dmp1 != NULL) {
		_goboringcrypto_BN_clear_free(r->dmp1);
		r->dmp1 = dmp1;
	}
	if (dmq1 != NULL) {
		_goboringcrypto_BN_clear_free(r->dmq1);
		r->dmq1 = dmq1;
	}
	if (iqmp != NULL) {
		_goboringcrypto_BN_clear_free(r->iqmp);
		r->iqmp = iqmp;
	}

	return 1;
#else
	return _goboringcrypto_internal_RSA_set0_crt_params(r, dmp1, dmq1, iqmp);
#endif
}

DEFINEFUNCINTERNAL(void, RSA_get0_crt_params,
		   (const GO_RSA *r, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmq1, const GO_BIGNUM **iqmp),
		   (r, dmp1, dmq1, iqmp))
static inline void
_goboringcrypto_RSA_get0_crt_params(const GO_RSA *r, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmq1, const GO_BIGNUM **iqmp) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	if (dmp1 != NULL)
		*dmp1 = r->dmp1;
	if (dmq1 != NULL)
		*dmq1 = r->dmq1;
	if (iqmp != NULL)
		*iqmp = r->iqmp;
#else
	_goboringcrypto_internal_RSA_get0_crt_params(r, dmp1, dmq1, iqmp);
#endif
}


DEFINEFUNCINTERNAL(int, RSA_set0_key,
		   (GO_RSA * r, GO_BIGNUM *n, GO_BIGNUM *e, GO_BIGNUM *d),
		   (r, n, e, d))
static inline int
_goboringcrypto_RSA_set0_key(GO_RSA * r, GO_BIGNUM *n, GO_BIGNUM *e, GO_BIGNUM *d) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	/* If the fields n and e in r are NULL, the corresponding input
	 * parameters MUST be non-NULL for n and e.  d may be
	 * left NULL (in case only the public key is used).
	 */
	if ((r->n == NULL && n == NULL)
		|| (r->e == NULL && e == NULL))
		return 0;

	if (n != NULL) {
		_goboringcrypto_BN_free(r->n);
		r->n = n;
	}
	if (e != NULL) {
		_goboringcrypto_BN_free(r->e);
		r->e = e;
	}
	if (d != NULL) {
		_goboringcrypto_BN_clear_free(r->d);
		r->d = d;
	}

	return 1;
#else
	return _goboringcrypto_internal_RSA_set0_key(r, n, e, d);
#endif
}

DEFINEFUNCINTERNAL(void, RSA_get0_factors,
		   (const GO_RSA *rsa, const GO_BIGNUM **p, const GO_BIGNUM **q),
		   (rsa, p, q))
static inline void 
_goboringcrypto_RSA_get0_factors(const GO_RSA *rsa, const GO_BIGNUM **p, const GO_BIGNUM **q) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	if (p)
		*p = rsa->p;
	if (q)
		*q = rsa->q;
#else
	_goboringcrypto_internal_RSA_get0_factors(rsa, p, q);
#endif
}

DEFINEFUNCINTERNAL(void, RSA_get0_key,
		   (const GO_RSA *rsa, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d),
		   (rsa, n, e, d))
static inline void 
_goboringcrypto_RSA_get0_key(const GO_RSA *rsa, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	if (n)
		*n = rsa->n;
	if (e)
		*e = rsa->e;
	if (d)
		*d = rsa->d;
#else
	_goboringcrypto_internal_RSA_get0_key(rsa, n, e, d);
#endif
}

int _goboringcrypto_RSA_generate_key_fips(GO_RSA *, int, GO_BN_GENCB *);
enum
{
	GO_RSA_PKCS1_PADDING = 1,
	GO_RSA_NO_PADDING = 3,
	GO_RSA_PKCS1_OAEP_PADDING = 4,
	GO_RSA_PKCS1_PSS_PADDING = 6,
};

int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA *, unsigned int *out_len, uint8_t *out, unsigned int max_out, const uint8_t *in, unsigned int in_len, GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len);

int _goboringcrypto_RSA_verify_pss_mgf1(GO_RSA *, const uint8_t *msg, unsigned int msg_len, GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len, const uint8_t *sig, unsigned int sig_len);

DEFINEFUNC(unsigned int, RSA_size, (const GO_RSA *arg0), (arg0))
DEFINEFUNC(int, RSA_check_key, (const GO_RSA *arg0), (arg0))

DEFINEFUNC(int, EVP_EncryptInit_ex,
	(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv),
	(ctx, type, impl, key, iv))
DEFINEFUNC(int, EVP_EncryptUpdate,
	(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),
	(ctx, out, outl, in, inl))
DEFINEFUNC(int, EVP_EncryptFinal_ex,
	(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl),
	(ctx, out, outl))

DEFINEFUNC(int, EVP_DecryptInit_ex,
	(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv),
	(ctx, type, impl, key, iv))
DEFINEFUNC(int, EVP_DecryptUpdate,
	(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),
	(ctx, out, outl, in, inl))
DEFINEFUNC(int, EVP_DecryptFinal_ex,
	(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl),
	(ctx, outm, outl))

DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_gcm, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_cbc, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ctr, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ecb, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_cbc, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ctr, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ecb, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_gcm, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_cbc, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ctr, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ecb, (void), ())
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_gcm, (void), ())

DEFINEFUNC(void, EVP_CIPHER_CTX_free, (EVP_CIPHER_CTX* arg0), (arg0))
DEFINEFUNC(int, EVP_CIPHER_CTX_ctrl, (EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr), (ctx, type, arg, ptr))

int _goboringcrypto_EVP_CIPHER_CTX_seal(
	uint8_t *out, uint8_t *nonce,
	uint8_t *aad, size_t aad_len,
	uint8_t *plaintext, size_t plaintext_len,
	size_t *ciphertext_len, uint8_t *key, int key_size);

int _goboringcrypto_EVP_CIPHER_CTX_open(
	uint8_t *ciphertext, int ciphertext_len,
	uint8_t *aad, int aad_len,
	uint8_t *tag, uint8_t *key, int key_size,
	uint8_t *nonce, int nonce_len,
	uint8_t *plaintext, size_t *plaintext_len);

typedef EVP_PKEY GO_EVP_PKEY;

DEFINEFUNC(GO_EVP_PKEY *, EVP_PKEY_new, (void), ())
DEFINEFUNC(void, EVP_PKEY_free, (GO_EVP_PKEY * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_set1_RSA, (GO_EVP_PKEY * arg0, GO_RSA *arg1), (arg0, arg1))
DEFINEFUNC(int, EVP_PKEY_verify,
	(EVP_PKEY_CTX *ctx, const unsigned char *sig, unsigned int siglen, const unsigned char *tbs, size_t tbslen),
	(ctx, sig, siglen, tbs, tbslen))

typedef EVP_PKEY_CTX GO_EVP_PKEY_CTX;

DEFINEFUNC(GO_EVP_PKEY_CTX *, EVP_PKEY_CTX_new, (GO_EVP_PKEY * arg0, ENGINE *arg1), (arg0, arg1))
DEFINEFUNC(void, EVP_PKEY_CTX_free, (GO_EVP_PKEY_CTX * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_CTX_ctrl,
		   (EVP_PKEY_CTX * ctx, int keytype, int optype, int cmd, int p1, void *p2),
		   (ctx, keytype, optype, cmd, p1, p2))
DEFINEFUNCINTERNAL(int, RSA_pkey_ctx_ctrl,
		   (EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2),
		   (ctx, optype, cmd, p1, p2))

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX* ctx, int pad) {
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
	return _goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL);
#else
	return _goboringcrypto_internal_RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL);
#endif
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX *ctx, uint8_t *l, int llen)
{

	return _goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)l);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX *ctx, const GO_EVP_MD *md)
{
	return _goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX * arg0, int arg1) {
	return _goboringcrypto_EVP_PKEY_CTX_ctrl(arg0, EVP_PKEY_RSA, 
		(EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), 
		EVP_PKEY_CTRL_RSA_PSS_SALTLEN, 
		arg1, NULL);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) {
	return _goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0, (void *)md);
}
static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX * ctx, const GO_EVP_MD *md) {
	return _goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,
						EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
								EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)md);
}

DEFINEFUNC(int, EVP_PKEY_decrypt,
		   (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4),
		   (arg0, arg1, arg2, arg3, arg4))
DEFINEFUNC(int, EVP_PKEY_encrypt,
		   (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4),
		   (arg0, arg1, arg2, arg3, arg4))
DEFINEFUNC(int, EVP_PKEY_decrypt_init, (GO_EVP_PKEY_CTX * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_encrypt_init, (GO_EVP_PKEY_CTX * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_sign_init, (GO_EVP_PKEY_CTX * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_verify_init, (GO_EVP_PKEY_CTX * arg0), (arg0))
DEFINEFUNC(int, EVP_PKEY_sign,
		   (GO_EVP_PKEY_CTX * arg0, uint8_t *arg1, size_t *arg2, const uint8_t *arg3, size_t arg4),
		   (arg0, arg1, arg2, arg3, arg4))
