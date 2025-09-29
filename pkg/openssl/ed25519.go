//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"runtime"
	"strconv"
	"sync"

	"github.com/microsoft/go/pkg/openssl/internal/ossl"
)

const (
	// publicKeySizeEd25519 is the size, in bytes, of public keys as used in crypto/ed25519.
	publicKeySizeEd25519 = 32
	// privateKeySizeEd25519 is the size, in bytes, of private keys as used in crypto/ed25519.
	privateKeySizeEd25519 = 64
	// signatureSizeEd25519 is the size, in bytes, of signatures generated and verified by crypto/ed25519.
	signatureSizeEd25519 = 64
	// seedSizeEd25519 is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

// TODO: Add support for Ed25519ph and Ed25519ctx when OpenSSL supports them,
// which will probably be in 3.2.0 (https://github.com/openssl/openssl/issues/20418).

var supportsEd25519 = sync.OnceValue(func() bool {
	switch vMajor {
	case 1:
		if versionAtOrAbove(1, 1, 1) {
			ctx, _ := ossl.EVP_PKEY_CTX_new_id(ossl.EVP_PKEY_ED25519, nil)
			if ctx != nil {
				ossl.EVP_PKEY_CTX_free(ctx)
				return true
			}
		}
	case 3:
		sig, _ := ossl.EVP_SIGNATURE_fetch(nil, _KeyTypeED25519.ptr(), nil)
		if sig != nil {
			ossl.EVP_SIGNATURE_free(sig)
			return true
		}
	}
	return false
})

// SupportsEd25519 returns true if the current OpenSSL version supports
// GenerateKeyEd25519, NewKeyFromSeedEd25519, SignEd25519 and VerifyEd25519.
func SupportsEd25519() bool {
	return supportsEd25519()
}

type PublicKeyEd25519 struct {
	_pkey ossl.EVP_PKEY_PTR
}

func (k *PublicKeyEd25519) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyEd25519) Bytes() ([]byte, error) {
	defer runtime.KeepAlive(k)
	pub := make([]byte, publicKeySizeEd25519)
	if err := extractPKEYPubEd25519(k._pkey, pub); err != nil {
		return nil, err
	}
	return pub, nil
}

type PrivateKeyEd25519 struct {
	_pkey ossl.EVP_PKEY_PTR
}

func (k *PrivateKeyEd25519) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyEd25519) Bytes() ([]byte, error) {
	defer runtime.KeepAlive(k)
	priv := make([]byte, privateKeySizeEd25519)
	if err := extractPKEYPrivEd25519(k._pkey, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func (k *PrivateKeyEd25519) Public() (*PublicKeyEd25519, error) {
	pub := make([]byte, publicKeySizeEd25519)
	if err := extractPKEYPubEd25519(k._pkey, pub); err != nil {
		return nil, err
	}
	pubk, err := NewPublicKeyEd25519(pub)
	if err != nil {
		return nil, err
	}
	return pubk, nil
}

// GenerateKeyEd25519 generates a private key.
func GenerateKeyEd25519() (*PrivateKeyEd25519, error) {
	pkeyPriv, err := generateEVPPKey(ossl.EVP_PKEY_ED25519, 0, "")
	if err != nil {
		return nil, err
	}
	priv := &PrivateKeyEd25519{_pkey: pkeyPriv}
	runtime.SetFinalizer(priv, (*PrivateKeyEd25519).finalize)
	return priv, nil
}

// Deprecated: use NewPrivateKeyEd25519 instead.
func NewPrivateKeyEd25119(priv []byte) (*PrivateKeyEd25519, error) {
	return NewPrivateKeyEd25519(priv)
}

func NewPrivateKeyEd25519(priv []byte) (*PrivateKeyEd25519, error) {
	if len(priv) != privateKeySizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(len(priv)))
	}
	return NewPrivateKeyEd25519FromSeed(priv[:seedSizeEd25519])
}

// Deprecated: use NewPublicKeyEd25519 instead.
func NewPublicKeyEd25119(pub []byte) (*PublicKeyEd25519, error) {
	return NewPublicKeyEd25519(pub)
}

func NewPublicKeyEd25519(pub []byte) (*PublicKeyEd25519, error) {
	if len(pub) != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(len(pub)))
	}
	pkey, err := ossl.EVP_PKEY_new_raw_public_key(ossl.EVP_PKEY_ED25519, nil, base(pub), len(pub))
	if err != nil {
		return nil, err
	}
	pubk := &PublicKeyEd25519{_pkey: pkey}
	runtime.SetFinalizer(pubk, (*PublicKeyEd25519).finalize)
	return pubk, nil
}

// NewPrivateKeyEd25519FromSeed calculates a private key from a seed. It will panic if
// len(seed) is not [SeedSize]. RFC 8032's private keys correspond to seeds in this
// package.
func NewPrivateKeyEd25519FromSeed(seed []byte) (*PrivateKeyEd25519, error) {
	if len(seed) != seedSizeEd25519 {
		panic("ed25519: bad seed length: " + strconv.Itoa(len(seed)))
	}
	pkey, err := ossl.EVP_PKEY_new_raw_private_key(ossl.EVP_PKEY_ED25519, nil, base(seed), len(seed))
	if err != nil {
		return nil, err
	}
	priv := &PrivateKeyEd25519{_pkey: pkey}
	runtime.SetFinalizer(priv, (*PrivateKeyEd25519).finalize)
	return priv, nil
}

func extractPKEYPubEd25519(pkey ossl.EVP_PKEY_PTR, pub []byte) error {
	keylen := publicKeySizeEd25519
	if _, err := ossl.EVP_PKEY_get_raw_public_key(pkey, base(pub), &keylen); err != nil {
		return err
	}
	if keylen != publicKeySizeEd25519 {
		return errors.New("ed25519: bad public key length: " + strconv.Itoa(keylen))
	}
	return nil
}

func extractPKEYPrivEd25519(pkey ossl.EVP_PKEY_PTR, priv []byte) error {
	if err := extractPKEYPubEd25519(pkey, priv[seedSizeEd25519:]); err != nil {
		return err
	}
	keylen := seedSizeEd25519
	if _, err := ossl.EVP_PKEY_get_raw_private_key(pkey, base(priv), &keylen); err != nil {
		return err
	}
	if keylen != seedSizeEd25519 {
		return errors.New("ed25519: bad private key length: " + strconv.Itoa(keylen))
	}
	return nil
}

// SignEd25519 signs the message with priv and returns a signature.
func SignEd25519(priv *PrivateKeyEd25519, message []byte) (sig []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	sig = make([]byte, signatureSizeEd25519)
	err = signEd25519(priv, sig, message)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func signEd25519(priv *PrivateKeyEd25519, sig, message []byte) error {
	defer runtime.KeepAlive(priv)
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return err
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if _, err := ossl.EVP_DigestSignInit(ctx, nil, nil, nil, priv._pkey); err != nil {
		return err
	}
	siglen := signatureSizeEd25519
	if _, err := ossl.EVP_DigestSign(ctx, base(sig), &siglen, base(message), len(message)); err != nil {
		return err
	}
	if siglen != signatureSizeEd25519 {
		return errors.New("ed25519: bad signature length: " + strconv.Itoa(siglen))
	}
	return nil
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub *PublicKeyEd25519, message, sig []byte) error {
	defer runtime.KeepAlive(pub)
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return err
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if _, err := ossl.EVP_DigestVerifyInit(ctx, nil, nil, nil, pub._pkey); err != nil {
		return err
	}
	if _, err := ossl.EVP_DigestVerify(ctx, base(sig), len(sig), base(message), len(message)); err != nil {
		return errors.New("ed25519: invalid signature")
	}
	return nil
}
