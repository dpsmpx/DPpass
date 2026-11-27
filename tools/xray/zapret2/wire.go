//go:build linux

package zapret2

import (
    "bufio"
    "bytes"
    "encoding/json"
    "errors"
    "io"
    "unicode/utf8"
)

const MaxRequestFrame = 48 * 1024
const MaxResponseFrame = 96 * 1024

// readFrame accepts one newline-terminated JSON message. ReadSlice stops
// at the buffer limit instead of allocating until a peer sends a newline.
// The bound includes the delimiter; no payload is retained or logged.
func readFrame(r io.Reader, limit int, dst any) error {
    reader:=bufio.NewReaderSize(r,limit+1)
    line,err:=reader.ReadSlice('\n')
    if err!=nil || len(line)>limit {return errors.New("invalid or oversized planner frame")}
    return decodePlannerJSON(line,dst)
}

// The wire uses exact object field names and base64 byte strings. Go's
// default decoder accepts duplicate/case-folded keys and numeric arrays;
// reject these ambiguous representations before decoding the typed value.
func decodePlannerJSON(raw []byte,dst any) error {
    if !utf8.Valid(raw) {return errors.New("invalid planner UTF-8")}
    fields:=json.NewDecoder(bytes.NewReader(raw))
    var schema string
    switch dst.(type) {
    case *Request: schema="request"
    case *Response: schema="response"
    default: return errors.New("invalid planner JSON type")
    }
    if err:=checkPlannerObject(fields,schema);err!=nil {return err}
    if _,err:=fields.Token();err!=io.EOF {return errors.New("trailing planner JSON")}
    dec:=json.NewDecoder(bytes.NewReader(raw))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(dst);err!=nil {return errors.New("invalid planner JSON")}
    var extra json.RawMessage
    if err:=dec.Decode(&extra);err!=io.EOF {return errors.New("trailing planner JSON")}
    return nil
}

func checkPlannerObject(dec *json.Decoder,schema string) error {
    token,err:=dec.Token()
    if err!=nil || token!=json.Delim('{') {return errors.New("planner JSON object required")}
    seen:=map[string]bool{}
    for dec.More() {
        key,err:=dec.Token()
        name,ok:=key.(string)
        if err!=nil || !ok || seen[name] {return errors.New("invalid or duplicate planner field")}
        seen[name]=true
        allowed:=false
        switch schema {
        case "request": allowed=name=="tag" || name=="network" || name=="first"
        case "response": allowed=name=="plan" || name=="error"
        case "plan":
            switch name {
            case "strategy","network","applied","cut","cut2","fake","rewrite","ttl","repeats","reason": allowed=true
            }
        }
        if !allowed {return errors.New("unknown planner field")}
        if schema=="response" && name=="plan" {
            if err:=checkPlannerObject(dec,"plan");err!=nil {return err}
            continue
        }
        value,err:=dec.Token()
        if err!=nil {return errors.New("invalid planner value")}
        // A nil first buffer is emitted as JSON null by the Go request
        // encoder. All other fields have a concrete scalar type.
        valid:=false
        switch name {
        case "first":
            _,valid=value.(string)
            valid=valid || value==nil
        case "applied":
            _,valid=value.(bool)
        case "cut","cut2","ttl","repeats":
            _,valid=value.(float64)
        default:
            _,valid=value.(string)
        }
        if !valid {return errors.New("invalid planner field type")}
    }
    end,err:=dec.Token()
    if err!=nil || end!=json.Delim('}') {return errors.New("invalid planner object")}
    var required []string
    switch schema {
    case "request": required=[]string{"tag","network","first"}
    case "response": required=[]string{"plan"}
    case "plan": required=[]string{"strategy","network","applied"}
    }
    for _,name:=range required {
        if !seen[name] {return errors.New("missing required planner field")}
    }
    return nil
}

// validateRequest is shared by IPC, the local planner and standalone CLI.
func validateRequest(tag,network string,first []byte) (Mode,error) {
    if len(first)>MaxFirst {return Mode{},errors.New("first packet too large")}
    mode,known,err:=ParseTag(tag)
    if err!=nil || !known || mode.Kind==Auto || (network!="tcp" && network!="udp") {
        return Mode{},errors.New("invalid planner request metadata")
    }
    return mode,nil
}

// ReadRequest validates framing before allocating any decoded payload.
func ReadRequest(r io.Reader) (Request,error) {
    var req Request
    if err:=readFrame(r,MaxRequestFrame,&req);err!=nil {return Request{},err}
    if _,err:=validateRequest(req.Tag,req.Network,req.First);err!=nil {return Request{},err}
    return req,nil
}

// ReadStandaloneRequest accepts a single bounded JSON object at EOF, with
// or without a final newline, for the existing --plan command.
func ReadStandaloneRequest(r io.Reader) (Request,error) {
    raw,err:=io.ReadAll(io.LimitReader(r,MaxRequestFrame+1))
    if err!=nil || len(raw)>MaxRequestFrame {return Request{},errors.New("invalid or oversized planner frame")}
    var req Request
    if err:=decodePlannerJSON(raw,&req);err!=nil {return Request{},err}
    if _,err:=validateRequest(req.Tag,req.Network,req.First);err!=nil {return Request{},err}
    return req,nil
}

func readResponse(r io.Reader) (Response,error) {
    var resp Response
    if err:=readFrame(r,MaxResponseFrame,&resp);err!=nil {return Response{},err}
    if resp.Error!="" {
        if resp.Plan.Strategy!="" || resp.Plan.Network!="" || resp.Plan.Applied ||
            resp.Plan.Cut!=0 || resp.Plan.Cut2!=0 || resp.Plan.TTL!=0 || resp.Plan.Repeats!=0 ||
            len(resp.Plan.Fake)!=0 || len(resp.Plan.Rewrite)!=0 || resp.Plan.Reason!="" {
            return Response{},errors.New("planner returned both error and plan")
        }
        return resp,nil
    }
    if resp.Plan.Strategy=="" || resp.Plan.Network=="" {
        return Response{},errors.New("missing planner response metadata")
    }
    return resp,nil
}
