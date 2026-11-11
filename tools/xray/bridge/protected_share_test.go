//go:build linux || windows

package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// Real SS2022 client/server traffic: knowing the server key alone cannot replace a revoked client key.
func TestProtectedShareAuthenticatesBothDirectionsAndRevokesClient(t *testing.T) {
	armSockets(nil)
	t.Cleanup(disarmSockets)
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	root, allowed, revoked := key(1), key(2), key(3)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	portListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	start := func(raw string) *core.Instance {
		t.Helper()
		conf, err := serial.DecodeJSONConfig(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		pb, err := conf.Build()
		if err != nil {
			t.Fatal(err)
		}
		inst, err := core.New(pb)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { inst.Close() })
		if err := inst.Start(); err != nil {
			t.Fatal(err)
		}
		return inst
	}
	// Test-only loopback listener; production checkPolicy separately enforces private tether addresses.
	start(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-256-gcm","password":%q,"clients":[{"password":%q}],"network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]}`, port, root, allowed))
	for _, tc := range []struct {
		name, root, client string
		want               bool
	}{
		{"paired", root, allowed, true}, {"revoked", root, revoked, false}, {"false gateway key", key(4), allowed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := start(fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"shadowsocks","settings":{"address":"127.0.0.1","port":%d,"method":"2022-blake3-aes-256-gcm","password":%q}}]}`, port, tc.root+":"+tc.client))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
			if err != nil {
				if tc.want {
					t.Fatal(err)
				}
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			message := []byte("protected echo")
			_, err = conn.Write(message)
			got := make([]byte, len(message))
			if err == nil {
				_, err = io.ReadFull(conn, got)
			}
			ok := err == nil && bytes.Equal(got, message)
			if ok != tc.want {
				t.Fatalf("authenticated echo=%v, want %v; error=%v", ok, tc.want, err)
			}
		})
	}
}
