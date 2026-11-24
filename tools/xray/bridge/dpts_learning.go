//go:build linux

package bridge

import (
    "errors"
    "math"
    "strings"
)

// TrainZapret2NeuralFromDPTS updates only the existing MLP's TLS/network
// contextual head. Kotlin independently checks 3/3 verified HTML responses
// on each of two same-pinned public IPv4 addresses (same HTTP/1.1 or HTTP/2 protocol) against a failed plain
// baseline. No raw host, IP, URL, cookie or body is ever accepted here.
// This cannot directly pin a strategy; live circuit breakers remain active.
func TrainZapret2NeuralFromDPTS(network, methodCSV string) error {
    networkID:=int32(0)
    switch network {
    case "MOBILE":networkID=1
    case "WIFI":networkID=2
    default:return errors.New("DPTS training requires stable MOBILE or WIFI context")
    }
    if zapret2NeuralNetwork.Load()!=networkID {
        return errors.New("network context changed before DPTS training")
    }
    methods:=strings.Split(methodCSV,",")
    if len(methods)<1 || len(methods)>6 {
        return errors.New("invalid DPTS neural method count")
    }
    seen:=make(map[string]struct{},len(methods))
    indices:=make([]int,0,len(methods))
    for _,method:=range methods {
        if _,exists:=seen[method];exists {
            return errors.New("duplicate DPTS neural method")
        }
        seen[method]=struct{}{}
        allowed:=false
        for _,m:=range []string{"split-1","split","fake-3","fake-5",
            "disorder","tlsrec-split"} {
            if method==m {allowed=true;break}
        }
        idx:=nnCandidateIndex(method,false)
        if !allowed || idx<0 || idx>=6 {
            return errors.New("unknown or unsupported DPTS neural method")
        }
        indices=append(indices,idx)
    }
    zapret2Neural.mu.Lock()
    defer zapret2Neural.mu.Unlock()
    w:=zapret2Neural.weights
    if w==nil || !nnModern(w) {
        return errors.New("current local contextual neural model is not installed")
    }
    ctx:=nnContext("www.youtube.com",false)
    if ctx<0 || ctx>=len(w.ContextBias) {
        return errors.New("invalid DPTS neural context")
    }
    for _,idx:=range indices {
        logit,_:=nnForward(w,"www.youtube.com",idx,false)
        prob:=1/(1+math.Exp(-math.Max(-12,math.Min(12,logit))))
        // Conservative supervised positive-label update. Content proof
        // shows only a bounded HTML GET, NOT authenticated feed or video.
        // No negative reward is inferred from ClientHello timeouts.
        delta:=0.02*(1-prob)
        w.ContextBias[ctx][idx]=nnClamp(w.ContextBias[ctx][idx]+delta)
        if w.Observations<1_000_000_000 {w.Observations++}
        if w.ContextObservations[ctx]<1_000_000_000 {
            w.ContextObservations[ctx]++
        }
    }
    zapret2Neural.dirty=true
    return nil
}
