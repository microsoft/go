// This file contains RSA portability wrappers.
// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goboringcrypto.h"

// Only in BoringSSL.
int _goboringcrypto_RSA_generate_key_fips(GO_RSA *rsa, int size, GO_BN_GENCB *cb)
{
	// BoringSSL's RSA_generate_key_fips hard-codes e to 65537.
	BIGNUM *e = _goboringcrypto_BN_new();
	if (e == NULL)
		return 0;
	int ret = _goboringcrypto_BN_set_word(e, RSA_F4) && _goboringcrypto_RSA_generate_key_ex(rsa, size, e, cb);
	_goboringcrypto_BN_free(e);
	return ret;
}

int _goboringcrypto_RSA_digest_and_sign_pss_mgf1(GO_RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
		const uint8_t *in, size_t in_len, EVP_MD *md, const EVP_MD *mgf1_md, int salt_len)
{
	EVP_PKEY_CTX *ctx;
	size_t siglen;

	EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
	if (!_goboringcrypto_EVP_PKEY_assign_RSA(key, rsa))
		return 0;
	ctx = _goboringcrypto_EVP_PKEY_CTX_new(key, NULL /* no engine */);
	if (!ctx)
		return 0;

	int ret = 0;

	EVP_MD_CTX *mdctx = NULL;
	if (!(mdctx = _goboringcrypto_EVP_MD_CTX_create()))
		goto err;

	if (1 != _goboringcrypto_EVP_DigestSignInit(mdctx, &ctx, md, NULL, key))
		goto err;

	if (_goboringcrypto_EVP_PKEY_sign_init(ctx) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
		goto err;

	if (1 != _goboringcrypto_EVP_DigestUpdate(mdctx, in, in_len))
		goto err;

	/* Obtain the signature length */
	if (1 != _goboringcrypto_EVP_DigestSignFinal(mdctx, NULL, out_len))
		goto err;
	/* Obtain the signature */
	if (1 != _goboringcrypto_EVP_DigestSignFinal(mdctx, out, out_len))
		goto err;

	ret = 1;

err:
	if (mdctx)
		_goboringcrypto_EVP_MD_CTX_free(mdctx);

	return ret;
}

int _goboringcrypto_RSA_digest_and_verify_pss_mgf1(RSA *rsa, const uint8_t *msg, size_t msg_len,
		EVP_MD *md, const EVP_MD *mgf1_md, int salt_len, const uint8_t *sig, size_t sig_len)
{
	EVP_PKEY_CTX *ctx;

	EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
	if (!_goboringcrypto_EVP_PKEY_assign_RSA(key, rsa))
		return 0;
	ctx = _goboringcrypto_EVP_PKEY_CTX_new(key, NULL /* no engine */);
	if (!ctx)
		return 0;

	int ret = 0;

	EVP_MD_CTX *mdctx = NULL;
	if (!(mdctx = _goboringcrypto_EVP_MD_CTX_create()))
		goto err;

	if (1 != _goboringcrypto_EVP_DigestVerifyInit(mdctx, &ctx, md, NULL, key))
		goto err;

	if (_goboringcrypto_EVP_PKEY_verify_init(ctx) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
		goto err;

	if (1 != _goboringcrypto_EVP_DigestUpdate(mdctx, msg, msg_len))
		goto err;

	if (1 != _goboringcrypto_EVP_DigestVerifyFinal(mdctx, sig, sig_len))
		goto err;

	/* Success */
	ret = 1;

err:
	if (mdctx)
		_goboringcrypto_EVP_MD_CTX_free(mdctx);

	return ret;
}

int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
		const uint8_t *in, size_t in_len, EVP_MD *md, const EVP_MD *mgf1_md, int salt_len) {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;
	size_t siglen;

	pkey = _goboringcrypto_EVP_PKEY_new();
	if (!pkey)
		return 0;

	if (_goboringcrypto_EVP_PKEY_set1_RSA(pkey, rsa) <= 0)
		return 0;
	
	ctx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
	if (!ctx)
		return 0;

	int ret = 0;

	if (_goboringcrypto_EVP_PKEY_sign_init(ctx) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
		goto err;
	
	/* Determine buffer length */
	if (_goboringcrypto_EVP_PKEY_sign(ctx, NULL, &siglen, in, in_len) <= 0)
		goto err;

	if (max_out < siglen)
		goto err;

	if (_goboringcrypto_EVP_PKEY_sign(ctx, out, &siglen, in, in_len) <= 0)
		goto err;

	*out_len = siglen;
	ret = 1;

err:
	_goboringcrypto_EVP_PKEY_CTX_free(ctx);

	return ret;
}

int _goboringcrypto_RSA_verify_pss_mgf1(RSA *rsa, const uint8_t *msg, size_t msg_len,
		EVP_MD *md, const EVP_MD *mgf1_md, int salt_len, const uint8_t *sig, size_t sig_len) {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;

	int ret = 0;

	pkey = _goboringcrypto_EVP_PKEY_new();
	if (!pkey)
		return 0;

	if (_goboringcrypto_EVP_PKEY_set1_RSA(pkey, rsa) <= 0)
		return 0;
	
	ctx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
	if (!ctx)
		return 0;

	if (_goboringcrypto_EVP_PKEY_verify_init(ctx) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
		goto err;
	if (_goboringcrypto_EVP_PKEY_verify(ctx, sig, sig_len, msg, msg_len) <= 0)
		goto err;

	ret = 1;

err:
	_goboringcrypto_EVP_PKEY_CTX_free(ctx);

	return ret;
}

int _goboringcrypto_EVP_RSA_sign(EVP_MD *md, const uint8_t *msg, size_t msgLen, uint8_t *sig, size_t *slen, RSA *rsa)
{
	EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
	if (!_goboringcrypto_EVP_PKEY_assign_RSA(key, rsa))
		return 0;
	return _goboringcrypto_EVP_sign(md, NULL, msg, msgLen, sig, slen, key);
}

int _goboringcrypto_EVP_RSA_verify(EVP_MD *md, const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t slen, GO_RSA *rsa)
{
	EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
	if (!_goboringcrypto_EVP_PKEY_assign_RSA(key, rsa))
	{
		return 0;
	}
	 return _goboringcrypto_EVP_verify(md, NULL, msg, msgLen, sig, slen, key);
}
