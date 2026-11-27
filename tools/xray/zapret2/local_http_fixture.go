//go:build linux

package zapret2

const localHTTPFixture = "POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody"

// LocalHTTPFixture returns an independently owned synthetic request.
func LocalHTTPFixture() []byte {return []byte(localHTTPFixture)}

// IsLocalHTTPFixture never treats a prefix or arbitrary Host as the
// fixed local diagnostic request.
func IsLocalHTTPFixture(first []byte) bool {return string(first)==localHTTPFixture}
