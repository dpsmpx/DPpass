// D-120: bounded DNS acceptance probe for the Android hotspot client.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	gateway := net.ParseIP(os.Args[1])
	if gateway == nil || gateway.To4() == nil || !gateway.IsPrivate() {
		os.Exit(2)
	}
	dialer := net.Dialer{Timeout: 4 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var inner error
		err := c.Control(func(fd uintptr) {
			inner = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "wlan0")
		})
		if err != nil {
			return err
		}
		return inner
	}}
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(gateway.String(), "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	answers, err := resolver.LookupIP(ctx, "ip4", "one.one.one.one.")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, ip := range answers {
		if ip.Equal(net.IPv4(1, 1, 1, 1)) || ip.Equal(net.IPv4(1, 0, 0, 1)) {
			fmt.Println(ip.String())
			return
		}
	}
	fmt.Fprintln(os.Stderr, "unexpected A answer")
	os.Exit(1)
}
