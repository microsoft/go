//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	pkey, err := generateEVPPKey(ossl.EVP_PKEY_RSA, int32(bits), "")
	if err != nil {
		return bad(err)
	}
	defer ossl.EVP_PKEY_free(pkey)
	switch vMajor {
	case 1:
		key, err := ossl.EVP_PKEY_get1_RSA(pkey)
		if err != nil {
			return bad(err)
		}
		defer ossl.RSA_free(key)
		var n, e, d, p, q, dmp1, dmq1, iqmp ossl.BIGNUM_PTR
		ossl.RSA_get0_key(key, &n, &e, &d)
		ossl.RSA_get0_factors(key, &p, &q)
		ossl.RSA_get0_crt_params(key, &dmp1, &dmq1, &iqmp)
		N, E, D = bnToBig(n), bnToBig(e), bnToBig(d)
		P, Q = bnToBig(p), bnToBig(q)
		Dp, Dq, Qinv = bnToBig(dmp1), bnToBig(dmq1), bnToBig(iqmp)
	case 3:
		tmp, err := ossl.BN_new()
		if err != nil {
			return bad(err)
		}
		defer func() {
			ossl.BN_clear_free(tmp)
		}()
		setBigInt := func(bi *BigInt, param cString) bool {
			if err != nil {
				return false
			}
			if _, err = ossl.EVP_PKEY_get_bn_param(pkey, param.ptr(), &tmp); err != nil {
				return false
			}
			*bi = bnToBig(tmp)
			ossl.BN_clear(tmp)
			return true
		}
		if !(setBigInt(&N, _OSSL_PKEY_PARAM_RSA_N) &&
			setBigInt(&E, _OSSL_PKEY_PARAM_RSA_E) &&
			setBigInt(&D, _OSSL_PKEY_PARAM_RSA_D) &&
			setBigInt(&P, _OSSL_PKEY_PARAM_RSA_FACTOR1) &&
			setBigInt(&Q, _OSSL_PKEY_PARAM_RSA_FACTOR2) &&
			setBigInt(&Dp, _OSSL_PKEY_PARAM_RSA_EXPONENT1) &&
			setBigInt(&Dq, _OSSL_PKEY_PARAM_RSA_EXPONENT2) &&
			setBigInt(&Qinv, _OSSL_PKEY_PARAM_RSA_COEFFICIENT1)) {
			return bad(err)
		}
	default:
		panic(errUnsupportedVersion())
	}
	return
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey ossl.EVP_PKEY_PTR
}

func NewPublicKeyRSA(n, e BigInt) (*PublicKeyRSA, error) {
	var pkey ossl.EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key, err := ossl.RSA_new()
		if err != nil {
			return nil, err
		}
		// No need to check for errors here, RSA_set0_* functions will fail
		// if the BNs are NULL and we will free non-NULL BNs in the error handling.
		bn, _ := bigToBN(n)
		be, _ := bigToBN(e)
		if _, err := ossl.RSA_set0_key(key, bn, be, nil); err != nil {
			ossl.BN_free(bn)
			ossl.BN_free(be)
			ossl.RSA_free(key)
			return nil, err
		}
		pkey, err = ossl.EVP_PKEY_new()
		if err != nil {
			ossl.RSA_free(key)
			return nil, err
		}
		if _, err := ossl.EVP_PKEY_assign(pkey, ossl.EVP_PKEY_RSA, (unsafe.Pointer)(key)); err != nil {
			ossl.RSA_free(key)
			ossl.EVP_PKEY_free(pkey)
			return nil, err
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(false, n, e, nil, nil, nil, nil, nil, nil); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	k := &PublicKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyRSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey ossl.EVP_PKEY_PTR
}

func NewPrivateKeyRSA(n, e, d, p, q, dp, dq, qinv BigInt) (*PrivateKeyRSA, error) {
	var pkey ossl.EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key, err := ossl.RSA_new()
		if err != nil {
			return nil, err
		}
		// No need to check for errors here, RSA_set0_* functions will fail
		// if the BNs are NULL and we will free non-NULL BNs in the error handling.
		bn, _ := bigToBN(n)
		be, _ := bigToBN(e)
		bd, _ := bigToBN(d)
		if _, err := ossl.RSA_set0_key(key, bn, be, bd); err != nil {
			ossl.BN_free(bn)
			ossl.BN_free(be)
			ossl.BN_clear_free(bd)
			return nil, err
		}
		if p != nil && q != nil {
			bp, _ := bigToBN(p)
			bq, _ := bigToBN(q)
			if _, err := ossl.RSA_set0_factors(key, bp, bq); err != nil {
				ossl.BN_clear_free(bp)
				ossl.BN_clear_free(bq)
				return nil, err
			}
		}
		if dp != nil && dq != nil && qinv != nil {
			bdp, _ := bigToBN(dp)
			bdq, _ := bigToBN(dq)
			bqinv, _ := bigToBN(qinv)
			if _, err := ossl.RSA_set0_crt_params(key, bdp, bdq, bqinv); err != nil {
				ossl.BN_free(bdp)
				ossl.BN_free(bdq)
				ossl.BN_free(bqinv)
				return nil, err
			}
		}
		pkey, err = ossl.EVP_PKEY_new()
		if err != nil {
			ossl.RSA_free(key)
			return nil, err
		}
		if _, err := ossl.EVP_PKEY_assign(pkey, ossl.EVP_PKEY_RSA, (unsafe.Pointer)(key)); err != nil {
			ossl.RSA_free(key)
			ossl.EVP_PKEY_free(pkey)
			return nil, err
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(true, n, e, d, p, q, dp, dq, qinv); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	k := &PrivateKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
}

func (k *PrivateKeyRSA) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyRSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, ossl.RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, ossl.RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, ossl.RSA_PKCS1_PADDING, nil, nil, nil, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, ossl.RSA_PKCS1_PADDING, nil, nil, nil, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	ret, err := evpDecrypt(priv.withKey, ossl.RSA_NO_PADDING, nil, nil, nil, ciphertext)
	if err != nil {
		return nil, err
	}
	// We could return here, but the Go standard library test expects DecryptRSANoPadding to verify the result
	// in order to defend against errors in the CRT computation.
	//
	// The following code tries to replicate the verification implemented in the upstream function decryptAndCheck, found at
	// https://github.com/golang/go/blob/9de1ac6ac2cad3871760d0aa288f5ca713afd0a6/src/crypto/rsa/rsa.go#L569-L582.
	pub := &PublicKeyRSA{_pkey: priv._pkey}
	// A private EVP_PKEY can be used as a public key as it contains the public information.
	enc, err := EncryptRSANoPadding(pub, ret)
	if err != nil {
		return nil, err
	}
	// Upstream does not do a constant time comparison because it works with math/big instead of byte slices,
	// and math/big does not support constant-time arithmetic yet. See #20654 for more info.
	if subtle.ConstantTimeCompare(ciphertext, enc) != 1 {
		return nil, errors.New("rsa: internal error")
	}
	return ret, nil
}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, ossl.RSA_NO_PADDING, nil, nil, nil, msg)
}

func saltLength(saltLen int, sign bool) (int32, error) {
	// A salt length of -2 is valid in OpenSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the OpenSSL sentinel values.
	if saltLen <= -2 {
		return 0, errors.New("crypto/rsa: invalid PSS salt length")
	}
	// OpenSSL uses sentinel salt length values like Go crypto does,
	// but the values don't fully match for rsa.PSSSaltLengthAuto (0).
	if saltLen == 0 {
		if sign {
			if vMajor == 1 {
				// OpenSSL 1.x uses -2 to mean maximal size when signing where Go crypto uses 0.
				return ossl.RSA_PSS_SALTLEN_MAX_SIGN, nil
			}
			// OpenSSL 3.x deprecated RSA_PSS_SALTLEN_MAX_SIGN
			// and uses -3 to mean maximal size when signing where Go crypto uses 0.
			return ossl.RSA_PSS_SALTLEN_MAX, nil
		}
		// OpenSSL uses -2 to mean auto-detect size when verifying where Go crypto uses 0.
		return ossl.RSA_PSS_SALTLEN_AUTO, nil
	}
	return int32(saltLen), nil
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	cSaltLen, err := saltLength(saltLen, true)
	if err != nil {
		return nil, err
	}
	return evpSign(priv.withKey, ossl.RSA_PKCS1_PSS_PADDING, cSaltLen, h, hashed)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	cSaltLen, err := saltLength(saltLen, false)
	if err != nil {
		return err
	}
	return evpVerify(pub.withKey, ossl.RSA_PKCS1_PSS_PADDING, cSaltLen, h, sig, hashed)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, ossl.RSA_PKCS1_PADDING, 0, h, hashed)
}

func HashSignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, msg []byte) ([]byte, error) {
	return evpHashSign(priv.withKey, h, msg)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	defer runtime.KeepAlive(pub)
	var size int32
	if err := pub.withKey(func(pkey ossl.EVP_PKEY_PTR) (err error) {
		size, err = ossl.EVP_PKEY_get_size(pkey)
		if err != nil {
			return err
		}
		if len(sig) < int(size) {
			return errors.New("crypto/rsa: verification error")
		}
		return nil
	}); err != nil {
		return err
	}
	return evpVerify(pub.withKey, ossl.RSA_PKCS1_PADDING, 0, h, sig, hashed)
}

func HashVerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, msg, sig []byte) error {
	return evpHashVerify(pub.withKey, h, msg, sig)
}

func newRSAKey3(isPriv bool, n, e, d, p, q, dp, dq, qinv BigInt) (ossl.EVP_PKEY_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()

	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_N, n, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_E, e, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_D, d, false)

	if p != nil && q != nil {
		allPrecomputedExists := dp != nil && dq != nil && qinv != nil
		// The precomputed values should only be passed if P and Q are present
		// and every precomputed value is present. (If any precomputed value is
		// missing, don't pass any of them.)
		//
		// In OpenSSL 3.0 and 3.1, we must also omit P and Q if any precomputed
		// value is missing. See https://github.com/openssl/openssl/pull/22334
		if vMinor >= 2 || allPrecomputedExists {
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR1, p, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR2, q, true)
		}
		if allPrecomputedExists {
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT1, dp, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT2, dq, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv, true)
		}
	}

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)
	selection := ossl.EVP_PKEY_PUBLIC_KEY
	if isPriv {
		selection = ossl.EVP_PKEY_KEYPAIR
	}
	return newEvpFromParams(ossl.EVP_PKEY_RSA, int32(selection), params)
}
