//go:build !linux || !cgo || !localdpi_native

package native

// Native execution is not available in the default build.
func SplitTLSRecord(_ []byte,_ int) ([]byte,bool) { return nil,false }

// Inspect cannot report a native observation in builds without the module.
func Inspect(_ []byte) (Hint,bool) {return Unknown,false}
