// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import _ "embed"

//go:embed header.md
var header string

type PlatformStatus struct {
	Supported         string
	MinGoVersion      string
	Notes             []string
	MinMacOSVersion   string
	MinOpenSSLVersion string
}

type Item struct {
	Name         string
	MinGoVersion string
	Notes        []string
	Platforms    map[string]PlatformStatus
}

type Section struct {
	Title             string
	ShortTitle        string
	ColumnHeader      string
	Packages          []string
	Description       string
	MinGoVersion      string
	MinMacOSVersion   string
	MinOpenSSLVersion string
	Items             []Item
	Subsections       []Section
	Footnotes         []string
	Footer            string
}

type Document struct {
	Sections []Section
}

var doc = Document{
	Sections: []Section{
		{
			Title: "Hash and Message Authentication Algorithms",
			Packages: []string{
				"crypto/md5",
				"crypto/sha1",
				"crypto/sha256",
				"crypto/sha512",
				"crypto/sha3",
				"crypto/hmac",
			},
			Items: []Item{
				{Name: "MD5"},
				{Name: "SHA-1"},
				{
					Name: "SHA-2-224",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
					},
				},
				{Name: "SHA-2-256"},
				{Name: "SHA-2-384"},
				{Name: "SHA-2-512"},
				{
					Name: "SHA-2-512_224",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"linux":   {MinGoVersion: "1.24", MinOpenSSLVersion: "1.1.1"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name: "SHA-2-512_256",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"linux":   {MinGoVersion: "1.24", MinOpenSSLVersion: "1.1.1"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name:         "SHA-3-224",
					MinGoVersion: "1.26",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"linux":   {MinOpenSSLVersion: "1.1.1"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name:         "SHA-3-256",
					MinGoVersion: "1.26",
					Platforms: map[string]PlatformStatus{
						"windows": {
							Notes: []string{"Available in Windows 11, version 24H2 or later."},
						},
						"linux": {MinOpenSSLVersion: "1.1.1"},
						"macos": {MinMacOSVersion: "26"},
					},
				},
				{
					Name:         "SHA-3-384",
					MinGoVersion: "1.26",
					Platforms: map[string]PlatformStatus{
						"windows": {
							Notes: []string{"Available in Windows 11, version 24H2 or later."},
						},
						"linux": {MinOpenSSLVersion: "1.1.1"},
						"macos": {MinMacOSVersion: "26"},
					},
				},
				{
					Name:         "SHA-3-512",
					MinGoVersion: "1.26",
					Platforms: map[string]PlatformStatus{
						"windows": {
							Notes: []string{"Available in Windows 11, version 24H2 or later."},
						},
						"linux": {MinOpenSSLVersion: "1.1.1"},
						"macos": {MinMacOSVersion: "26"},
					},
				},
				{
					Name: "SHAKE-128",
					Platforms: map[string]PlatformStatus{
						"linux": {MinOpenSSLVersion: "3.3"},
						"macos": {Supported: "false"},
					},
				},
				{
					Name: "SHAKE-256",
					Platforms: map[string]PlatformStatus{
						"linux": {MinOpenSSLVersion: "3.3"},
						"macos": {Supported: "false"},
					},
				},
				{
					Name: "CSHAKE-128",
					Platforms: map[string]PlatformStatus{
						"linux": {Supported: "false"},
						"macos": {Supported: "false"},
					},
				},
				{
					Name: "CSHAKE-256",
					Platforms: map[string]PlatformStatus{
						"linux": {Supported: "false"},
						"macos": {Supported: "false"},
					},
				},
				{
					Name: "HMAC",
					Notes: []string{
						"Supports only hash algorithms that are supported as standalone hash functions.",
					},
				},
			},
		},
		{
			Title:        "Symmetric encryption",
			ColumnHeader: "Cipher + Mode",
			Packages:     []string{"crypto/aes", "crypto/cipher", "crypto/des", "crypto/rc4"},
			Footer:       "- Key Sizes\n\n  AES-GCM works with 128, 192, and 256-bit keys.\n\n- Nonce Sizes\n\n  AES-GCM works with 12-byte nonces.\n\n- Tag Sizes\n\n  AES-GCM works with 16-byte tags.",
			Items: []Item{
				{Name: "AES-ECB"},
				{Name: "AES-CBC"},
				{
					Name: "AES-CTR",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name: "AES-CFB",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"linux":   {Supported: "false"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name: "AES-OFB",
					Platforms: map[string]PlatformStatus{
						"windows": {Supported: "false"},
						"linux":   {Supported: "false"},
						"macos":   {Supported: "false"},
					},
				},
				{
					Name:  "AES-GCM",
					Notes: []string{"AES-GCM supports specific keys, nonces, and tags:"},
				},
				{
					Name: "DES-CBC",
					Platforms: map[string]PlatformStatus{
						"linux": {
							Supported: "warn",
							Notes: []string{
								"When using OpenSSL 3, requires the legacy provider to be enabled.",
							},
						},
					},
				},
				{
					Name: "DES-ECB",
					Platforms: map[string]PlatformStatus{
						"linux": {
							Supported: "warn",
							Notes: []string{
								"When using OpenSSL 3, requires the legacy provider to be enabled.",
							},
						},
					},
				},
				{Name: "3DES-ECB"},
				{Name: "3DES-CBC"},
				{
					Name: "RC4",
					Platforms: map[string]PlatformStatus{
						"linux": {
							Supported: "warn",
							Notes: []string{
								"When using OpenSSL 3, requires the legacy provider to be enabled.",
							},
						},
					},
				},
			},
		},
		{
			Title:       "Asymmetric encryption",
			Packages:    []string{"RSA", "ECDSA", "ECDH", "Ed25519", "DSA"},
			Description: "",
			Subsections: []Section{
				{
					Title:        "RSA",
					ColumnHeader: "Padding Mode",
					Packages:     []string{"crypto/rsa"},
					Description:  "[rsa.GenerateKey](https://pkg.go.dev/crypto/rsa#GenerateKey) only supports the following key sizes (in bits): 2048, 3072, 4096.\n\nMulti-prime RSA keys are not supported.\n\nThe RSA key size is subject to the limitations of the underlying cryptographic library.\nFor example, on some Windows and SCOSSL configurations, the key size should be multiple of 8.\nPlease refer to the documentation of the underlying cryptographic library for the specific limitations.\n\nOperations that require random numbers (rand io.Reader) only support [rand.Reader](https://pkg.go.dev/crypto/rand#Reader).",
					Items: []Item{
						{
							Name: "OAEP (MD5)",
							Platforms: map[string]PlatformStatus{
								"macos": {
									Notes: []string{
										"macOS doesn't support passing a custom label to OAEP functions.",
									},
								},
							},
						},
						{
							Name: "OAEP (SHA-1)",
							Platforms: map[string]PlatformStatus{
								"macos": {
									Notes: []string{
										"macOS doesn't support passing a custom label to OAEP functions.",
									},
								},
							},
						},
						{
							Name: "OAEP (SHA-2)",
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
							Platforms: map[string]PlatformStatus{
								"macos": {
									Notes: []string{
										"macOS doesn't support passing a custom label to OAEP functions.",
									},
								},
							},
						},
						{
							Name: "OAEP (SHA-3)",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
						{
							Name: "PSS (MD5)",
							Platforms: map[string]PlatformStatus{
								"windows": {
									Notes: []string{
										"On Windows, when verifying a PSS signature, [rsa.PSSSaltLengthAuto](https://pkg.go.dev/crypto/rsa#pkg-constants) is not supported.",
									},
								},
								"macos": {Supported: "false"},
							},
						},
						{
							Name: "PSS (SHA-1)",
							Platforms: map[string]PlatformStatus{
								"windows": {
									Notes: []string{
										"On Windows, when verifying a PSS signature, [rsa.PSSSaltLengthAuto](https://pkg.go.dev/crypto/rsa#pkg-constants) is not supported.",
									},
								},
								"macos": {
									Notes: []string{
										"On macOS, custom salt lengths are not supported. PSS always uses the [`rsa.PSSSaltLengthEqualsHash`](https://pkg.go.dev/crypto/rsa#pkg-constants).",
									},
								},
							},
						},
						{
							Name: "PSS (SHA-2)",
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
							Platforms: map[string]PlatformStatus{
								"windows": {
									Notes: []string{
										"On Windows, when verifying a PSS signature, [rsa.PSSSaltLengthAuto](https://pkg.go.dev/crypto/rsa#pkg-constants) is not supported.",
									},
								},
								"macos": {
									Notes: []string{
										"On macOS, custom salt lengths are not supported. PSS always uses the [`rsa.PSSSaltLengthEqualsHash`](https://pkg.go.dev/crypto/rsa#pkg-constants).",
									},
								},
							},
						},
						{
							Name: "PSS (SHA-3)",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
						{Name: "PKCS1v15 Signature (Unhashed)"},
						{
							Name: "PKCS1v15 Signature (RIPMED160)",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {MinGoVersion: "1.24"},
								"macos":   {Supported: "false"},
							},
						},
						{
							Name: "PKCS1v15 Signature (MD4)",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {MinGoVersion: "1.24"},
								"macos":   {Supported: "false"},
							},
						},
						{
							Name: "PKCS1v15 Signature (MD5)",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
						{
							Name: "PKCS1v15 Signature (MD5-SHA1)",
							Platforms: map[string]PlatformStatus{
								"windows": {MinGoVersion: "1.24"},
								"linux":   {MinGoVersion: "1.24"},
								"macos":   {Supported: "false"},
							},
						},
						{Name: "PKCS1v15 Signature (SHA-1)"},
						{
							Name: "PKCS1v15 Signature (SHA-2)",
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
						{
							Name: "PKCS1v15 Signature (SHA-3)",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
					},
				},
				{
					Title:        "ECDSA",
					ColumnHeader: "Elliptic Curve",
					Packages:     []string{"crypto/ecdsa", "crypto/elliptic"},
					Description:  "Operations that require random numbers (rand io.Reader) only support [rand.Reader](https://pkg.go.dev/crypto/rand#Reader).",
					Items: []Item{
						{
							Name: "NIST P-224 (secp224r1)",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
						{Name: "NIST P-256 (secp256r1)"},
						{Name: "NIST P-384 (secp384r1)"},
						{Name: "NIST P-521 (secp521r1)"},
					},
				},
				{
					Title:        "ECDH",
					ColumnHeader: "Elliptic Curve",
					Packages:     []string{"crypto/ecdh"},
					Description:  "Operations that require random numbers (rand io.Reader) only support [rand.Reader](https://pkg.go.dev/crypto/rand#Reader).",
					Items: []Item{
						{
							Name: "NIST P-224 (secp224r1)",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
						{Name: "NIST P-256 (secp256r1)"},
						{Name: "NIST P-384 (secp384r1)"},
						{Name: "NIST P-521 (secp521r1)"},
						{
							Name:         "X25519 (curve25519)",
							MinGoVersion: "1.26",
							Platforms: map[string]PlatformStatus{
								"linux": {MinOpenSSLVersion: "1.1.1"},
							},
						},
					},
				},
				{
					Title:        "Ed25519",
					ColumnHeader: "Schemes",
					Packages:     []string{"crypto/ed25519"},
					Description:  "Operations that require random numbers (rand io.Reader) only support [rand.Reader](https://pkg.go.dev/crypto/rand#Reader).",
					Items: []Item{
						{
							Name: "Ed25519",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
							},
						},
						{
							Name: "Ed25519ctx",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
						{
							Name: "Ed25519ph",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"linux":   {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
					},
				},
				{
					Title:        "DSA",
					ColumnHeader: "Parameters",
					Items: []Item{
						{
							Name: "L1024N160",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
						{
							Name: "L2048N224",
							Platforms: map[string]PlatformStatus{
								"windows": {Supported: "false"},
								"macos":   {Supported: "false"},
							},
						},
						{
							Name: "L2048N256",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
						{
							Name: "L3072N256",
							Platforms: map[string]PlatformStatus{
								"macos": {Supported: "false"},
							},
						},
					},
				},
			},
		},
		{
			Title:        "Key derivation functions (KDFs)",
			ColumnHeader: "Functions",
			Packages:     []string{"crypto/hkdf", "crypto/pbkdf2"},
			Items: []Item{
				{
					Name: "PBKDF2",
					Platforms: map[string]PlatformStatus{
						"windows": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
						"linux": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
						"macos": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
					},
				},
				{
					Name: "HKDF",
					Platforms: map[string]PlatformStatus{
						"windows": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
						"linux": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
						"macos": {
							Notes: []string{
								"Supports only hash algorithms that are [supported as standalone hash functions](#hash-and-message-authentication-algorithms).",
							},
						},
					},
				},
			},
		},
		{
			Title:    "Key Encapsulation Mechanisms (KEMs)",
			Packages: []string{"ML-KEM"},
			Subsections: []Section{
				{
					Title:        "ML-KEM",
					ColumnHeader: "Parameters",
					Packages:     []string{"crypto/mlkem"},
					MinGoVersion: "1.26",
					Items: []Item{
						{
							Name: "768",
							Platforms: map[string]PlatformStatus{
								"windows": {
									Notes: []string{
										"Requires Windows Server 2025 or Windows 11 (24H2, 25H2) or later.",
									},
								},
								"linux": {MinOpenSSLVersion: "3.5.0"},
								"macos": {MinMacOSVersion: "26"},
							},
						},
						{
							Name: "1024",
							Platforms: map[string]PlatformStatus{
								"windows": {
									Notes: []string{
										"Requires Windows Server 2025 or Windows 11 (24H2, 25H2) or later.",
									},
								},
								"linux": {MinOpenSSLVersion: "3.5.0"},
								"macos": {MinMacOSVersion: "26"},
							},
						},
					},
				},
			},
		},
		{
			Title:       "Higher-level protocols",
			Packages:    []string{"HPKE", "TLS"},
			Description: "High-level protocols are algorithms that combine multiple cryptographic primitives to provide a specific functionality,\nsuch as TLS or Hybrid Public Key Encryption (HPKE).\n\nThese protocols are implemented using native Go code, but they rely on the underlying OS cryptographic libraries for the cryptographic operations.\n\nThis section includes the following subsections:",
			Subsections: []Section{
				{
					Title:    "Hybrid Public Key Encryption (HPKE)",
					Packages: []string{"AEAD Functions", "KDFs", "KEMs", "crypto/hpke"},
					Subsections: []Section{
						{
							Title:        "HPKE Authenticated Encryption with Associated Data (AEAD) Functions",
							ColumnHeader: "Functions",
							ShortTitle:   "AEAD Functions",
							Items: []Item{
								{Name: "AES-128-GCM"},
								{Name: "AES-256-GCM"},
								{
									Name:         "ChaCha20Poly1305",
									MinGoVersion: "1.26",
								},
								{
									Name: "Export-only",
									Platforms: map[string]PlatformStatus{
										"windows": {Supported: "N/A"},
										"linux":   {Supported: "N/A"},
										"macos":   {Supported: "N/A"},
									},
								},
							},
						},
						{
							Title:        "HPKE Key Derivation Functions (KDFs)",
							ColumnHeader: "Functions",
							ShortTitle:   "KDFs",
							Items: []Item{
								{Name: "HKDF-SHA256"},
								{Name: "HKDF-SHA384"},
								{Name: "HKDF-SHA512"},
							},
						},
						{
							Title:        "HPKE Key Encapsulation Mechanisms (KEMs)",
							ColumnHeader: "Functions",
							ShortTitle:   "KEMs",
							Items: []Item{
								{Name: "DHKEM(P-256, HKDF-SHA256)"},
								{Name: "DHKEM(P-384, HKDF-SHA384)"},
								{Name: "DHKEM(P-521, HKDF-SHA512)"},
								{
									Name:  "DHKEM(X25519, HKDF-SHA256)",
									Notes: []string{"See the [X25519](#ecdh) section for requirements."},
								},
								{
									Name: "ML-KEM-768",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "ML-KEM-1024",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "MLKEM768-P256",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "MLKEM1024-P384",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "MLKEM768-X25519",
									Notes: []string{
										"See the [X25519](#ecdh) section for requirements.",
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
							},
						},
					},
				},
				{
					Title: "TLS",
					Packages: []string{
						"TLS Versions",
						"TLS Cipher Suites",
						"TLS Curves and Groups",
						"TLS Signature Schemes",
						"crypto/tls",
					},
					Subsections: []Section{
						{
							Title:        "TLS Versions",
							ColumnHeader: "Version",
							Description:  "The TLS stack is implemented using native Go code but the crypto primitives are provided by the system cryptographic libraries.",
							Items: []Item{
								{
									Name: "SSL 3.0",
									Platforms: map[string]PlatformStatus{
										"windows": {Supported: "false"},
										"linux":   {Supported: "false"},
										"macos":   {Supported: "false"},
									},
								},
								{
									Name: "TLS 1.0",
									Platforms: map[string]PlatformStatus{
										"macos": {Supported: "false"},
									},
								},
								{
									Name: "TLS 1.1",
									Platforms: map[string]PlatformStatus{
										"macos": {Supported: "false"},
									},
								},
								{Name: "TLS 1.2"},
								{Name: "TLS 1.3"},
							},
						},
						{
							Title:        "TLS Cipher Suites",
							ColumnHeader: "Name",
							Footer:       "On Windows, it is possible to restrict and reorder the cipher suites following the [Schannel preferences](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel) by building with the `ms_tls_config_schannel` goexperiment enabled.",
							Items: []Item{
								{
									Name: "TLS_RSA_WITH_RC4_128_SHA",
									Platforms: map[string]PlatformStatus{
										"linux": {
											Supported: "warn",
											Notes: []string{
												"When using OpenSSL 3, requires the legacy provider to be enabled.",
											},
										},
									},
								},
								{
									Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
									Platforms: map[string]PlatformStatus{
										"linux": {
											Supported: "warn",
											Notes: []string{
												"When using OpenSSL 3, requires the legacy provider to be enabled.",
											},
										},
									},
								},
								{Name: "TLS_RSA_WITH_AES_128_CBC_SHA"},
								{Name: "TLS_RSA_WITH_AES_256_CBC_SHA"},
								{Name: "TLS_RSA_WITH_AES_128_CBC_SHA256"},
								{Name: "TLS_RSA_WITH_AES_128_GCM_SHA256"},
								{Name: "TLS_RSA_WITH_AES_256_GCM_SHA384"},
								{
									Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
									Platforms: map[string]PlatformStatus{
										"linux": {
											Supported: "warn",
											Notes: []string{
												"When using OpenSSL 3, requires the legacy provider to be enabled.",
											},
										},
									},
								},
								{Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
								{Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
								{
									Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
									Platforms: map[string]PlatformStatus{
										"linux": {
											Supported: "warn",
											Notes: []string{
												"When using OpenSSL 3, requires the legacy provider to be enabled.",
											},
										},
									},
								},
								{
									Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
									Platforms: map[string]PlatformStatus{
										"linux": {
											Supported: "warn",
											Notes: []string{
												"When using OpenSSL 3, requires the legacy provider to be enabled.",
											},
										},
									},
								},
								{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
								{Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
								{Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
								{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
								{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
								{Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
								{Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
								{Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
								{
									Name:         "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
									MinGoVersion: "1.26",
								},
								{
									Name:         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
									MinGoVersion: "1.26",
								},
								{Name: "TLS_AES_128_GCM_SHA256"},
								{Name: "TLS_AES_256_GCM_SHA384"},
								{
									Name:         "TLS_CHACHA20_POLY1305_SHA256",
									MinGoVersion: "1.26",
								},
								{
									Name:         "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
									MinGoVersion: "1.26",
								},
								{
									Name:         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
									MinGoVersion: "1.26",
								},
							},
						},
						{
							Title:        "TLS Curves and Groups",
							ColumnHeader: "Name",
							Description:  "Below are the supported [`tls.CurveIDs`](https://pkg.go.dev/crypto/tls#CurveID).",
							Items: []Item{
								{Name: "CurveP256"},
								{Name: "CurveP384"},
								{Name: "CurveP521"},
								{
									Name:  "X25519",
									Notes: []string{"See the [X25519](#ecdh) section for requirements."},
								},
								{
									Name: "X25519MLKEM768",
									Notes: []string{
										"See the [X25519](#ecdh) section for requirements.",
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "SecP256r1MLKEM768",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
								{
									Name: "SecP384r1MLKEM1024",
									Notes: []string{
										"See the [ML-KEM](#ml-kem) section for requirements.",
									},
								},
							},
						},
						{
							Title:        "TLS Signature Schemes",
							ColumnHeader: "Name",
							Description:  "Below are the supported [`tls.SignatureSchemes`](https://pkg.go.dev/crypto/tls#SignatureScheme).",
							Items: []Item{
								{Name: "PKCS1WithSHA1"},
								{Name: "PKCS1WithSHA256"},
								{Name: "PKCS1WithSHA384"},
								{Name: "PKCS1WithSHA512"},
								{Name: "PSSWithSHA256"},
								{Name: "PSSWithSHA384"},
								{Name: "PSSWithSHA512"},
								{Name: "ECDSAWithSHA1"},
								{Name: "ECDSAWithP256AndSHA256"},
								{Name: "ECDSAWithP384AndSHA384"},
								{Name: "ECDSAWithP521AndSHA512"},
								{
									Name: "Ed25519",
									Platforms: map[string]PlatformStatus{
										"windows": {Supported: "false"},
									},
								},
							},
						},
					},
				},
			},
		},
	},
}
