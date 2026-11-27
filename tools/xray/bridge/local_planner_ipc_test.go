//go:build linux

package bridge

import (
    "encoding/json"
    "net"
    "os"
    "path/filepath"
    "sync"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

// A real Unix stream using the same public decoder/planner as the Alpine
// process. It does not claim to run Alpine or test Android permissions.
func TestLocalDiagnosticsThroughSelectedPlannerIPC(t *testing.T) {
    dir,err:=os.MkdirTemp("","dpp-ipc-")
    if err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = os.RemoveAll(dir)})
    path:=filepath.Join(dir,"p.sock")
    listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:path,Net:"unix"})
    if err!=nil {t.Fatal(err)}
    var mu sync.Mutex
    calls:=map[string]int{}
    done:=make(chan struct{})
    go func(){
        defer close(done)
        for {
            c,err:=listener.AcceptUnix()
            if err!=nil {return}
            func(){
                defer c.Close()
                _=c.SetDeadline(time.Now().Add(2*time.Second))
                req,err:=zapret2.ReadRequest(c)
                if err!=nil {return}
                plan,err:=zapret2.BuildPlan(req.Tag,req.Network,req.First)
                if err!=nil {return}
                mu.Lock()
                calls[req.Tag]++
                mu.Unlock()
                _=json.NewEncoder(c).Encode(zapret2.Response{Plan:plan})
            }()
        }
    }()
    t.Cleanup(func(){_ = listener.Close();<-done})
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(path);err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    for _,tc:=range []struct{target,method,outcome string}{
        {"local_http_hostcase","plain","local_http_verified"},
        {"local_http_hostcase","http-hostcase","local_http_verified"},
        {"local_http_hostcase","http-hostows","local_http_verified"},
        {"local_tls12","plain","local_tls_verified"},
        {"local_tls13","plain","local_tls_verified"},
        {"local_tls12","multisplit","local_tls_verified"},
        {"local_tls13","multisplit","local_tls_verified"},
        {"local_tls12","tlsrec-split","local_tls_verified"},
        {"local_tls13","tlsrec-split","local_tls_verified"},
    } {
        r:=ProbeZapret2HTTPS(tc.method,tc.target,5*time.Second)
        expected:=int64(1)
        if tc.method=="plain" {expected=0}
        if r.Outcome!=tc.outcome || r.AppliedDelta!=expected || r.SkippedDelta!=0 {
            t.Fatalf("%s/%s: %+v",tc.target,tc.method,r)
        }
    }
    mu.Lock()
    defer mu.Unlock()
    if calls[zapret2.TagPrefix+"http-hostcase"]!=1 ||
        calls[zapret2.TagPrefix+"http-hostows"]!=1 ||
        calls[zapret2.TagPrefix+"multisplit"]!=2 ||
        calls[zapret2.TagPrefix+"plain"]!=0 {
        t.Fatal("unexpected IPC requests",calls)
    }
    // The tagged ByeDPI encoder may intentionally plan TLS records locally.
    if n:=calls[zapret2.TagPrefix+"tlsrec-split"];n!=0 && n!=2 {
        t.Fatal("mixed TLS-record backend",n)
    }
}
