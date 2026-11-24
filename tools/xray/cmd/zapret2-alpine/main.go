//go:build linux

// zapret2-alpine is the portable strategy planner. The Alpine daemon uses
// app-private Unix-domain sockets; no raw sockets, NFQUEUE, or host root.
package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "os"
    "strings"
    "syscall"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func request(req zapret2.Request) zapret2.Response {
    if len(req.First) > zapret2.MaxFirst { return zapret2.Response{Error:"first packet too large"} }
    plan, err := zapret2.BuildPlan(req.Tag, req.Network, req.First)
    if err != nil { return zapret2.Response{Error:err.Error()} }
    return zapret2.Response{Plan:plan}
}

func serve(path string) error {
    if path == "" || !strings.HasPrefix(path, "/") || len(path) > 99 { return errors.New("socket requires absolute path <=99 chars") }
    if _, err := os.Lstat(path); err == nil { return errors.New("socket already exists (do not remove unknown file)") } else if !os.IsNotExist(err) { return err }
    old := syscall.Umask(0077)
    listener, err := net.Listen("unix", path)
    syscall.Umask(old)
    if err != nil { return err }
    defer listener.Close()
    defer os.Remove(path)
    gate := newConnectionGate(maxPlannerConnections)
    for {
        conn, err := listener.Accept()
        if err != nil { return err }
        gate.start(conn, handleConnection)
    }
}

func handleConnection(c net.Conn) {
    if err:=c.SetDeadline(time.Now().Add(3*time.Second));err!=nil {return}
    req,err:=zapret2.ReadRequest(c)
    if err!=nil {return}
    _ = json.NewEncoder(c).Encode(request(req))
}

func main() {
    if len(os.Args) == 2 && os.Args[1] == "--list" {
        for _, s := range zapret2.Profiles() { fmt.Println(s) }
        return
    }
    if len(os.Args) == 3 && os.Args[1] == "--serve" {
        if err := serve(os.Args[2]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
        return
    }
    if len(os.Args) == 2 && os.Args[1] == "--plan" {
        dec := json.NewDecoder(os.Stdin)
        var req zapret2.Request
        if err := dec.Decode(&req); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
        _ = json.NewEncoder(os.Stdout).Encode(request(req))
        return
    }
    fmt.Fprintln(os.Stderr, "usage: zapret2-alpine --list | --plan | --serve /absolute/private/socket")
    os.Exit(2)
}
