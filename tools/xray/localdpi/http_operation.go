package localdpi

import "bytes"

// HTTPHostNameCase is an isolated portable HTTP/1.x field-name operation.
// It preserves the authority value, request target, framing and body.
// Not registered as an AUTO method or an executor capability.
func HTTPHostNameCase(first []byte) ([]byte,bool) {
    field,ok:=httpHostField(first)
    if !ok {return nil,false}
    out:=bytes.Clone(first)
    copy(out[field.nameStart:field.nameStart+4],"hOSt")
    return out,true
}

// PreservesHTTPHostNameCase requires the same valid header offsets in
// both buffers and exact equality of all bytes outside the Host name.
func PreservesHTTPHostNameCase(original,rewritten []byte) bool {
    if len(original)!=len(rewritten) {return false}
    a,ok:=httpHostField(original)
    if !ok {return false}
    b,ok:=httpHostField(rewritten)
    if !ok || a!=b {return false}
    return bytes.Equal(original[:a.nameStart],rewritten[:a.nameStart]) &&
        bytes.Equal(original[a.nameStart+4:],rewritten[a.nameStart+4:])
}
