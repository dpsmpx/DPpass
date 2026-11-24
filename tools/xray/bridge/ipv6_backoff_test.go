//go:build linux

package bridge

import ("net"; "syscall"; "testing"; "time")

func TestIPv6BackoffRequiresRouteErrorsAndExpires(t *testing.T) {
    var b ipv6Backoff
    now := time.Unix(100,0)
    v6 := net.ParseIP("2001:db8::1")
    v4 := net.ParseIP("192.0.2.1")
    if b.skip(v6, 1, now) { t.Fatal("initial skip") }
    b.result(v6,1,now,syscall.EHOSTUNREACH)
    b.result(v6,1,now,syscall.ENETUNREACH)
    if b.skip(v6,1,now) { t.Fatal("only one route failure") }
    b.result(v6,1,now,syscall.ENETUNREACH)
    if !b.skip(v6,1,now) || b.skip(v4,1,now) { t.Fatal("wrong family") }
    if b.skip(v6,1,now.Add(16*time.Second)) { t.Fatal("cooldown not expired") }
    b.result(v6,1,now.Add(16*time.Second),syscall.ENETUNREACH)
    if !b.skip(v6,1,now.Add(17*time.Second)) { t.Fatal("missing retry backoff") }
    if b.skip(v6,2,now.Add(17*time.Second)) { t.Fatal("old network poisoned new network") }
}
