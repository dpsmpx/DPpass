//go:build !linux || !cgo || !localdpi_native

package native

// Native execution is not available in the default build.
func SplitTLSRecord(_ []byte,_ int) ([]byte,bool) { return nil,false }

// Inspect cannot report a native observation in builds without the module.
func Inspect(_ []byte) (Hint,bool) {return Unknown,false}

// The portable build cannot claim independent native parser agreement.
func TLSNameAgrees(_ []byte) bool {return false}

// No native HTTP mutation is available in the portable build.
func HTTPHostCaseFixture(_ []byte) ([]byte,bool) {return nil,false}
