// Package target replays one input against a fuzz target and reports what it
// reached. The coordinator re-runs every worker claim through the same
// Executor, so a worker's own measurements are never trusted.
package target

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"fuzzpool/internal/coverage"
)

// Crash is a reproducible failure. Signature is stable across runs and
// inputs that hit the same bug, so the same bug is paid for only once.
type Crash struct {
	Kind      string   `json:"kind"`
	Signature string   `json:"signature"`
	Frames    []string `json:"frames"`
}

type Result struct {
	Edges []coverage.Edge
	Crash *Crash
}

// Executor replays a single input. A returned error means the executor itself
// failed (missing binary, sandbox error), never that the target crashed.
type Executor interface {
	// Digest pins the exact target build. Campaigns record it, and workers
	// refuse leases for a build they are not running.
	Digest() string
	Execute(ctx context.Context, input []byte) (Result, error)
}

// Signature derives a crash identity from its kind and top stack frames.
func Signature(kind string, frames []string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, f := range frames {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}
