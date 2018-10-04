// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testcert contains a test-only localhost certificate.
package testcert

import "strings"

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var LocalhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIRALnQ833F+ldkJgxLTBi7tbEwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMEFghlvOWNGahq8Ma8ElZq24MxRRAgePxkP4RZMfSUUuTCcA2yE
/mSrPNc49coNZL2rjSgu57U6KgMVvXwWrNKO3+IW1rR6vRq0N+g03bGh3SrnwnIi
vtFbbuMNE2t48lKnRSSRaQVWa0C0O21JJ321ACN4AfaIMowRFUUr8fomwgIPXjtI
3rMnE0oQFNkecWs5s/QmzyyPPPNxJUhBRoWg3MLhY+Sq8AkP/WCF4yxnFoDS8t69
CJjpFVq9ueNIIkOS8B3ylUti7l0FCSUfD8Xs5eYPkcOB7BzA0amk21In6WzzUjX8
qw8db4dzu8o3w9RuWMQzYrV1tlhcDP5HW5kCAwEAAaNoMGYwDgYDVR0PAQH/BAQD
AgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wLgYDVR0R
BCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZI
hvcNAQELBQADggEBAAgjasMo7y6NR8f6/3uzCSXD+Ynor02lBDC2yPkH6eEkQJpT
2oNt+YoQ5zw0SLV57/O9AykXWbmOgPQzkjjHkYq32qJCfc//O4of2v289R6cwqAB
xWha9R3bFvjJH7EFMFj18e37rDYeX85BZeX90+SKc4OtIqzJBKUz5a0FJd7+Zkzu
YrHaK5vIN0mY4WcK1wrFemf9GOQVdM1azEgPP+HoYQwMZMmqbV126OO6VO5tY4c+
arFYI9vA69ld00mrLmuaoQsODO/Xk30bPonTndmDuPqHYzkw7/OZk7YgmaCy2a21
b8jUqQAurcSkb59lX6+DDP2M+IhJK8/PTDaFyS4=
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for LocalhostCert.
var LocalhostKey = []byte(testingKey(`-----BEGIN RSA TESTING KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA TESTING KEY-----`))

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
