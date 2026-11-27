//go:build linux

package zapret2

import "testing"

func TestLocalHTTPFixtureOwnershipAndExactMatch(t *testing.T) {
    first:=LocalHTTPFixture()
    if !IsLocalHTTPFixture(first) {t.Fatal("fixture not recognized")}
    for i:=range first {
        b:=LocalHTTPFixture()
        b[i]^=1
        if IsLocalHTTPFixture(b) || IsLocalHTTPFixture(first[:i]) {t.Fatal("partial or changed fixture admitted",i)}
    }
    first[0]^=1
    if !IsLocalHTTPFixture(LocalHTTPFixture()) {t.Fatal("fixture mutated")}
}
