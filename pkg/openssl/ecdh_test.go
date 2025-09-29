package openssl_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/microsoft/go/pkg/openssl"
)

func TestECDH(t *testing.T) {
	for _, tt := range []string{"P-256", "P-384", "P-521"} {
		t.Run(tt, func(t *testing.T) {
			name := tt
			aliceKey, alicPrivBytes, err := openssl.GenerateKeyECDH(name)
			if err != nil {
				t.Fatal(err)
			}
			bobKey, _, err := openssl.GenerateKeyECDH(name)
			if err != nil {
				t.Fatal(err)
			}

			alicePubKeyFromPriv, err := aliceKey.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			alicePubBytes := alicePubKeyFromPriv.Bytes()
			want := len(alicPrivBytes)
			var got int
			if tt == "X25519" {
				got = len(alicePubBytes)
			} else {
				got = (len(alicePubBytes) - 1) / 2 // subtract encoding prefix and divide by the number of components
			}
			if want != got {
				t.Fatalf("public key size mismatch: want: %v, got: %v", want, got)
			}
			alicePubKey, err := openssl.NewPublicKeyECDH(name, alicePubBytes)
			if err != nil {
				t.Fatal(err)
			}

			bobPubKeyFromPriv, err := bobKey.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			_, err = openssl.NewPublicKeyECDH(name, bobPubKeyFromPriv.Bytes())
			if err != nil {
				t.Error(err)
			}

			bobSecret, err := openssl.ECDH(bobKey, alicePubKey)
			if err != nil {
				t.Fatal(err)
			}
			aliceSecret, err := openssl.ECDH(aliceKey, bobPubKeyFromPriv)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(bobSecret, aliceSecret) {
				t.Error("two ECDH computations came out different")
			}
		})
	}
}

// The following vectors have been copied from
// https://github.com/golang/go/blob/bb0d8297d76cb578baad8fa1485565d9acf44cc5/src/crypto/ecdh/ecdh_test.go.

var ecdhvectors = []struct {
	Name                  string
	PrivateKey, PublicKey string
	PeerPublicKey         string
	SharedSecret          string
}{
	// NIST vectors from CAVS 14.1, ECC CDH Primitive (SP800-56A).
	{
		Name:       "P-256",
		PrivateKey: "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
		PublicKey: "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230" +
			"28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
		PeerPublicKey: "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287" +
			"db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
		SharedSecret: "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
	},
	{
		Name:       "P-384",
		PrivateKey: "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
		PublicKey: "049803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f" +
			"ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
		PeerPublicKey: "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066" +
			"ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
		SharedSecret: "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
	},
	// For some reason all field elements in the test vector (both scalars and
	// base field elements), but not the shared secret output, have two extra
	// leading zero bytes (which in big-endian are irrelevant). Removed here.
	{
		Name:       "P-521",
		PrivateKey: "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
		PublicKey: "0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5" +
			"01b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
		PeerPublicKey: "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d" +
			"01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
		SharedSecret: "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
	},
}

func TestECDHVectors(t *testing.T) {
	for _, tt := range ecdhvectors {
		t.Run(tt.Name, func(t *testing.T) {
			key, err := openssl.NewPrivateKeyECDH(tt.Name, hexDecode(t, tt.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := key.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			got, want := pub.Bytes(), hexDecode(t, tt.PublicKey)
			if !bytes.Equal(got, want) {
				t.Error("public key derived from the private key does not match")
			}
			peer, err := openssl.NewPublicKeyECDH(tt.Name, hexDecode(t, tt.PeerPublicKey))
			if err != nil {
				t.Fatal(err)
			}
			got, err = openssl.ECDH(key, peer)
			if err != nil {
				t.Fatal(err)
			}
			want = hexDecode(t, tt.SharedSecret)
			if !bytes.Equal(got, want) {
				t.Error("shared secret does not match")
			}
		})
	}
}

func hexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid hex string:", s)
	}
	return b
}

func BenchmarkECDH(b *testing.B) {
	const curve = "P-256"
	aliceKey, _, err := openssl.GenerateKeyECDH(curve)
	if err != nil {
		b.Fatal(err)
	}
	bobKey, _, err := openssl.GenerateKeyECDH(curve)
	if err != nil {
		b.Fatal(err)
	}

	alicePubKey, err := aliceKey.PublicKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := openssl.ECDH(bobKey, alicePubKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

var invalidECDHPrivateKeys = map[string][]string{
	"P-256": {
		// Bad lengths.
		"",
		"01",
		"01010101010101010101010101010101010101010101010101010101010101",
		"000101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"0000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	},
	"P-384": {
		// Bad lengths.
		"",
		"01",
		"0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		"00010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	},
	"P-521": {
		// Bad lengths.
		"",
		"01",
		"0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		"00010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
		"11fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		"03fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4a30d0f077e5f2cd6ff980291ee134ba0776b937113388f5d76df6e3d2270c812",
	},
}

var invalidECDHPublicKeys = map[string][]string{
	"P-256": {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"02e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
		// Points not on the curve.
		"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
		"0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	"P-384": {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"0208d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
		// Points not on the curve.
		"04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e60",
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	"P-521": {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"030035b5df64ae2ac204c354b483487c9070cdc61c891c5ff39afc06c5d55541d3ceac8659e24afe3d0750e8b88e9f078af066a1d5025b08e5a5e2fbc87412871902f3",
		"0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		// Points not on the curve.
		"0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16651",
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
}

func TestECDHNewPrivateKeyECDH_Invalid(t *testing.T) {
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		t.Run(curve, func(t *testing.T) {
			for _, input := range invalidECDHPrivateKeys[curve] {
				k, err := openssl.NewPrivateKeyECDH(curve, hexDecode(t, input))
				if err == nil {
					t.Errorf("unexpectedly accepted %q", input)
				} else if k != nil {
					t.Error("PrivateKey was not nil on error")
				}
			}
		})
	}
}

func TestECDHNewPublicKeyECDH_Invalid(t *testing.T) {
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		t.Run(curve, func(t *testing.T) {
			for _, input := range invalidECDHPublicKeys[curve] {
				k, err := openssl.NewPublicKeyECDH(curve, hexDecode(t, input))
				if err == nil {
					t.Errorf("unexpectedly accepted %q", input)
				} else if k != nil {
					t.Error("PublicKey was not nil on error")
				}
			}
		})
	}
}
