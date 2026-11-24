//go:build !linux || !cgo || !localdpi_native

package native

// Native execution is not available in the default build.
func SplitTLSRecord(_ []byte,_ int) ([]byte,bool) { return nil,false }
