//go:build linux

package bridge

import (
    "bytes"
    "encoding/json"
    "errors"
    "io"
    "unicode/utf8"
)

// The typed decoder remains authoritative for dimensions and values.
// This bounded preflight rejects ambiguities that encoding/json otherwise
// silently accepts, including duplicate fields and null numeric elements.
func checkModelJSON(raw []byte, allowHTML bool) error {
    invalid:=errors.New("ambiguous neural model JSON")
    if len(raw)==0 || len(raw)>adaptiveNNMaxBytes || !utf8.Valid(raw) {return invalid}
    d:=json.NewDecoder(bytes.NewReader(raw))
    d.UseNumber()
    var value func(int) error
    value=func(depth int) error {
        if depth>4 {return invalid}
        tok,err:=d.Token()
        if err!=nil {return invalid}
        if depth==0 && tok!=json.Delim('{') {return invalid}
        if tok==nil && depth!=1 {return invalid}
        switch tok {
        case json.Delim('{'):
            seen:=make(map[string]struct{})
            for d.More() {
                key,err:=d.Token()
                name,ok:=key.(string)
                if err!=nil || !ok {return invalid}
                if _,ok:=seen[name];ok {return invalid}
                seen[name]=struct{}{}
                if depth==0 && !modelJSONField(name, allowHTML) {return invalid}
                if err:=value(depth+1);err!=nil {return err}
            }
            close,err:=d.Token()
            if err!=nil || close!=json.Delim('}') {return invalid}
        case json.Delim('['):
            for d.More() {if err:=value(depth+1);err!=nil {return err}}
            close,err:=d.Token()
            if err!=nil || close!=json.Delim(']') {return invalid}
        }
        return nil
    }
    if err:=value(0);err!=nil {return err}
    if _,err:=d.Token();err!=io.EOF {return invalid}
    return nil
}

func modelJSONField(s string, allowHTML bool) bool {
    switch s {
    case "format","parameters","seed","hidden","bias","deep_hidden","deep_bias",
        "output","output_bias","context_bias","context_observations","sparse","observations":
        return true
    case "verified_html_bias", "verified_html_observations":
        return allowHTML
    default:return false
    }
}
