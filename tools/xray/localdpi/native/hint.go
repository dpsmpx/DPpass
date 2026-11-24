package native

// Hint is deliberately weaker than a complete protocol recognition.
// A positive hint must never substitute for the common parser, a
// verified response or a runtime capability declaration.
type Hint uint8

const (
    Unknown Hint = iota
    TLSCandidate
    HTTPCandidate
)

const MaxInspect = 16384
