//go:build linux

package bridge

import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "errors"
    "math"
    "strings"
)

// TrainZapret2NeuralFromDPTS updates a separate verified HTML calibration
// for this exact service and network, never the passive transport MLP. Kotlin independently checks 3/3 verified HTML responses
// on each of two same-pinned public IPv4 addresses (same HTTP/1.1 or HTTP/2 protocol) against a failed plain
// baseline. No raw host, IP, URL, cookie or body is ever accepted here.
// This cannot directly pin a strategy; live circuit breakers remain active.
func DPTSGeneration() int64 { return int64(zapret2Auto.generationSnapshot()) }

func TrainZapret2NeuralFromDPTS(network, methodCSV string, generation int64) error {
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
    if len(methods)<1 || len(methods)>localdpi.LegacyTCPOutputs {
        return errors.New("invalid DPTS neural method count")
    }
    seen:=make(map[string]struct{},len(methods))
    indices:=make([]int,0,len(methods))
    for _,method:=range methods {
        if _,exists:=seen[method];exists {
            return errors.New("duplicate DPTS neural method")
        }
        seen[method]=struct{}{}
        idx:=localdpi.LegacyHTMLIndex(method)
        if idx<0 || !socketCapabilities.Allows(localdpi.TLS,method) {
            return errors.New("unknown or unsupported DPTS neural method")
        }
        indices=append(indices,idx)
    }
    // Match the selector -> neural lock order already used for passive
    // learning. A reset cannot interleave with a verified calibration.
    zapret2Auto.mu.Lock()
    defer zapret2Auto.mu.Unlock()
    if generation<0 || uint64(generation)!=zapret2Auto.generation {
        return errors.New("DPTS session generation changed")
    }
    zapret2Neural.mu.Lock()
    defer zapret2Neural.mu.Unlock()
    // The initial check is only an early rejection. Recheck under the
    // same lock as network configuration before changing any weights.
    if zapret2NeuralNetwork.Load()!=networkID {
        return errors.New("network context changed before DPTS training")
    }
    w:=zapret2Neural.weights
    if w==nil || !nnModern(w) {
        return errors.New("current local contextual neural model is not installed")
    }
    ctx:=nnContext("www.youtube.com",false)/3
    if ctx<0 || ctx>=3 { return errors.New("invalid DPTS neural context") }
    if len(w.VerifiedHTMLBias)==0 {
        w.VerifiedHTMLBias=make([][]float64,3)
        for i:=range w.VerifiedHTMLBias { w.VerifiedHTMLBias[i]=make([]float64,localdpi.LegacyTCPOutputs) }
        w.VerifiedHTMLObservations=make([]int,3)
    }
    for _,idx:=range indices {
        logit:=w.VerifiedHTMLBias[ctx][idx]
        prob:=1/(1+math.Exp(-math.Max(-12,math.Min(12,logit))))
        // Conservative supervised positive-label update. Content proof
        // shows only a bounded HTML GET, NOT authenticated feed or video.
        // No negative reward is inferred from ClientHello timeouts.
        delta:=0.02*(1-prob)
        w.VerifiedHTMLBias[ctx][idx]=nnClamp(w.VerifiedHTMLBias[ctx][idx]+delta)
        if w.Observations<1_000_000_000 {w.Observations++}
        if w.VerifiedHTMLObservations[ctx]<1_000_000_000 {
            w.VerifiedHTMLObservations[ctx]++
        }
    }
    zapret2Neural.dirty=true
    return nil
}
