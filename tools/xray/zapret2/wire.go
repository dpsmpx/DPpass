//go:build linux

package zapret2

import (
    "bufio"
    "bytes"
    "encoding/json"
    "errors"
    "io"
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
    dec:=json.NewDecoder(bytes.NewReader(line))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(dst);err!=nil {return errors.New("invalid planner JSON")}
    var extra json.RawMessage
    if err:=dec.Decode(&extra);err!=io.EOF {return errors.New("trailing planner JSON")}
    return nil
}

// ReadRequest validates framing before allocating any decoded payload.
func ReadRequest(r io.Reader) (Request,error) {
    var req Request
    if err:=readFrame(r,MaxRequestFrame,&req);err!=nil {return Request{},err}
    if len(req.First)>MaxFirst {return Request{},errors.New("first packet too large")}
    mode,known,err:=ParseTag(req.Tag)
    if err!=nil || !known || mode.Kind==Auto ||
        (req.Network!="tcp" && req.Network!="udp") {
        return Request{},errors.New("invalid planner request metadata")
    }
    return req,nil
}

func readResponse(r io.Reader) (Response,error) {
    var resp Response
    if err:=readFrame(r,MaxResponseFrame,&resp);err!=nil {return Response{},err}
    if resp.Error!="" {
        if resp.Plan.Strategy!="" || resp.Plan.Network!="" || resp.Plan.Applied ||
            resp.Plan.Cut!=0 || resp.Plan.TTL!=0 || resp.Plan.Repeats!=0 ||
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
