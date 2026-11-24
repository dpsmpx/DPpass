//go:build !linux || !cgo || !localdpi_native

package native

import "testing"

func TestDefaultInspectionUnavailable(t *testing.T) {
    if hint,ok:=Inspect([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));ok || hint!=Unknown {
        t.Fatal("default build claimed native capability")
    }
}
