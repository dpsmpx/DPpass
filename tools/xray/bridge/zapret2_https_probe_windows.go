//go:build windows

package bridge

import (
    "fmt"
    "time"
)

// The one-click Google strategy matrix is Android/Linux-only. Keep the
// shared JNI ABI linkable on Windows without opening any test connection.
type Zapret2HTTPSResult struct {
    Outcome string
    HTTPStatus int
    BodyBytes int64
    Elapsed time.Duration
    AppliedDelta int64
    SkippedDelta int64
}

func (r Zapret2HTTPSResult) Wire() []byte {
    return []byte(fmt.Sprintf("v1\t%s\t%d\t%d\t%d\t%d\t%d",
        r.Outcome, r.HTTPStatus, r.BodyBytes, r.Elapsed.Milliseconds(),
        r.AppliedDelta, r.SkippedDelta))
}

func ProbeZapret2HTTPS(_ string, _ time.Duration) Zapret2HTTPSResult {
    return Zapret2HTTPSResult{Outcome:"unsupported"}
}
