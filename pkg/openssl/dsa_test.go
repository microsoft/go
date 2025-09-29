package openssl_test

import (
	"crypto/dsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/microsoft/go/pkg/openssl"
	"github.com/microsoft/go/pkg/openssl/bbig"
)

type dsaSignature struct {
	R, S *big.Int
}

func TestDSAGenerateParameters(t *testing.T) {
	if !openssl.SupportsDSA() {
		t.Skip("DSA is not supported")
	}

	var tests = []struct {
		L, N int
	}{
		{1024, 160},
		{2048, 224},
		{2048, 256},
		{3072, 256},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-%d", test.L, test.N), func(t *testing.T) {
			if openssl.FIPS() {
				t.Skip("generating DSA parameters with L = 2048 is not supported in FIPS mode")
			}
			testGenerateParametersDSA(t, test.L, test.N)
		})
	}
}

func testGenerateParametersDSA(t *testing.T, L, N int) {
	params, err := openssl.GenerateParametersDSA(L, N)
	if err != nil {
		t.Errorf("error generating parameters: %s", err)
		return
	}

	P := bbig.Dec(params.P)
	Q := bbig.Dec(params.Q)
	G := bbig.Dec(params.G)

	if P.BitLen() != L {
		t.Errorf("params.BitLen got:%d want:%d", P.BitLen(), L)
	}

	if Q.BitLen() != N {
		t.Errorf("q.BitLen got:%d want:%d", Q.BitLen(), L)
	}

	one := new(big.Int)
	one.SetInt64(1)
	pm1 := new(big.Int).Sub(P, one)
	quo, rem := new(big.Int).DivMod(pm1, Q, new(big.Int))
	if rem.Sign() != 0 {
		t.Error("p-1 mod q != 0")
	}
	if x := new(big.Int).Exp(G, quo, P); x.Cmp(one) == 0 {
		t.Error("invalid generator")
	}

	x, y, err := openssl.GenerateKeyDSA(params)
	if err != nil {
		t.Errorf("error generating key: %s", err)
		return
	}
	priv, err := openssl.NewPrivateKeyDSA(params, x, y)
	if err != nil {
		t.Errorf("error creating key: %s", err)
	}
	testDSASignAndVerify(t, priv)
}

func testDSASignAndVerify(t *testing.T, priv *openssl.PrivateKeyDSA) {
	hashed := []byte("testing")
	sig, err := openssl.SignDSA(priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}
	pub, err := openssl.NewPublicKeyDSA(priv.DSAParameters, priv.Y)
	if err != nil {
		t.Errorf("error getting public key: %s", err)
		return
	}
	if !openssl.VerifyDSA(pub, hashed, sig) {
		t.Error("error verifying")
		return
	}

	// Test compatibility with crypto/dsa.
	priv1 := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: bbig.Dec(priv.P),
				Q: bbig.Dec(priv.Q),
				G: bbig.Dec(priv.G),
			},
			Y: bbig.Dec(priv.Y),
		},
		X: bbig.Dec(priv.X),
	}
	var esig dsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		t.Error(err)
		return
	}
	if !dsa.Verify(&priv1.PublicKey, hashed, esig.R, esig.S) {
		t.Error("compat: crypto/dsa can't verify OpenSSL signature")
	}
	r1, s1, err := dsa.Sign(openssl.RandReader, &priv1, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}
	sig, err = asn1.Marshal(dsaSignature{r1, s1})
	if err != nil {
		t.Error(err)
		return
	}
	if !openssl.VerifyDSA(pub, hashed, sig) {
		t.Error("compat: OpenSSL can't verify crypto/dsa signature")
		return
	}
}

func TestDSASignAndVerify(t *testing.T) {
	if !openssl.SupportsDSA() {
		t.Skip("DSA is not supported")
	}
	if openssl.FIPS() {
		t.Skip("DSA signing with L = 2048 is not supported in FIPS mode")
	}

	params := openssl.DSAParameters{
		P: bbig.Enc(fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")),
		Q: bbig.Enc(fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1")),
		G: bbig.Enc(fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")),
	}
	Y := bbig.Enc(fromHex("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"))
	X := bbig.Enc(fromHex("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A"))
	priv, err := openssl.NewPrivateKeyDSA(params, X, Y)
	if err != nil {
		t.Fatalf("error generating key: %s", err)
	}

	testDSASignAndVerify(t, priv)
}

func TestDSANewPrivateKeyWithDegenerateKeys(t *testing.T) {
	if !openssl.SupportsDSA() {
		t.Skip("DSA is not supported")
	}

	// Signing with degenerate private keys should not cause an infinite loop
	badKeys := []struct {
		p, q, g, y, x string
	}{
		{"00", "01", "00", "00", "00"},
		{"01", "ff", "00", "00", "00"},
	}

	for i, test := range badKeys {
		params := openssl.DSAParameters{
			P: bbig.Enc(fromHex(test.p)),
			Q: bbig.Enc(fromHex(test.q)),
			G: bbig.Enc(fromHex(test.g)),
		}
		x, y := bbig.Enc(fromHex(test.x)), bbig.Enc(fromHex(test.y))
		priv, err := openssl.NewPrivateKeyDSA(params, x, y)
		if err != nil {
			// Some OpenSSL 1 fails to create degenerated private keys, which is fine.
			continue
		}
		hashed := []byte("testing")
		if _, err := openssl.SignDSA(priv, hashed); err == nil {
			t.Errorf("#%d: unexpected success", i)
		}
	}
}

func TestDSANewPublicKeyWithBadPublicKey(t *testing.T) {
	if !openssl.SupportsDSA() {
		t.Skip("DSA is not supported")
	}

	params := openssl.DSAParameters{
		P: bbig.Enc(fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")),
		Q: bbig.Enc(fromHex("FA")),
		G: bbig.Enc(fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")),
	}
	Y := bbig.Enc(fromHex("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"))

	pub, err := openssl.NewPublicKeyDSA(params, Y)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(dsaSignature{fromHex("2"), fromHex("4")})
	if err != nil {
		t.Fatal(err)
	}
	if openssl.VerifyDSA(pub, []byte("testing"), sig) {
		t.Errorf("Unexpected success with non-existent mod inverse of Q")
	}
}

func fromHex(s string) *big.Int {
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return result
}
