//go:build linux

package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

type generationTestDialer struct {
	dial func() (net.Conn, error)
}

func (d generationTestDialer) Dial(context.Context, xnet.Address, xnet.Destination, *internet.SocketConfig) (net.Conn, error) {
	return d.dial()
}

func (generationTestDialer) DestIpAddress() net.IP { return nil }

func TestDesyncDialGenerationSurvivesHandover(t *testing.T) {
	t.Cleanup(ResetZapret2AdaptiveLearning)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: "dppass:exp-auto"}})
	t.Run("TCP", func(t *testing.T) {
		out, peer := tcpCopyPair(t)
		dialer := &desyncDialer{base: generationTestDialer{dial: func() (net.Conn, error) {
			ResetZapret2AdaptiveLearning()
			return out, nil
		}}}
		dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(peer.LocalAddr().(*net.TCPAddr).Port))
		conn, err := dialer.Dial(ctx, nil, dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		request := []byte("GET / HTTP/1.1\r\nHost: handover.example.test\r\n\r\n")
		if n, err := conn.Write(request); err != nil || n != len(request) {
			t.Fatalf("write after handover: %d %v", n, err)
		}
		received := make([]byte, len(request))
		if _, err := io.ReadFull(peer, received); err != nil || !bytes.Equal(request, received) {
			t.Fatalf("old-generation TCP did not pass original bytes: %v", err)
		}
		wrapped := conn.(*desyncConn)
		if wrapped.adaptiveGeneration == zapret2Auto.generationSnapshot() || wrapped.adaptiveSelection.Load() != nil {
			t.Fatal("old generation published a TCP observation")
		}
		assertNoHandoverEntries(t)
	})
	t.Run("QUIC", func(t *testing.T) {
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		addr := peer.LocalAddr().(*net.UDPAddr)
		dialer := &desyncDialer{base: generationTestDialer{dial: func() (net.Conn, error) {
			ResetZapret2AdaptiveLearning()
			return net.DialUDP("udp4", nil, addr)
		}}}
		conn, err := dialer.Dial(ctx, nil, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		initial := make([]byte, 1200)
		initial[0], initial[4] = 0xc0, 1
		if n, err := conn.Write(initial); err != nil || n != len(initial) {
			t.Fatalf("write after handover: %d %v", n, err)
		}
		received := make([]byte, len(initial))
		if n, err := peer.Read(received); err != nil || n != len(initial) || !bytes.Equal(initial, received) {
			t.Fatalf("old-generation QUIC did not pass original bytes: %d %v", n, err)
		}
		wrapped := conn.(*desyncUDPConn)
		if wrapped.adaptiveGeneration == zapret2Auto.generationSnapshot() || wrapped.adaptiveSelection.Load() != nil {
			t.Fatal("old generation published a QUIC observation")
		}
		assertNoHandoverEntries(t)
	})
}

func assertNoHandoverEntries(t *testing.T) {
	t.Helper()
	zapret2Auto.mu.Lock()
	defer zapret2Auto.mu.Unlock()
	if len(zapret2Auto.entries) != 0 {
		t.Fatal("old-generation connection used the new cache")
	}
}
