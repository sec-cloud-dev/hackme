package target

import (
	"context"
	"fmt"
	"path"
	"runtime"
	"slices"
	"strings"

	"fuzzpool/internal/coverage"
)

// TinyParse is a deterministic, self-instrumented demo target with two
// planted bugs. It lets the whole pipeline run without clang or AFL++; real
// campaigns use Binary instead.
type TinyParse struct{}

func (TinyParse) Digest() string { return "builtin:tinyparse@v1" }

func (TinyParse) Execute(ctx context.Context, input []byte) (res Result, err error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	tr := &tracer{}
	defer func() {
		if r := recover(); r != nil {
			res = Result{Edges: tr.edges(), Crash: crashFromPanic(r)}
			err = nil
		}
	}()
	tinyParse(tr, input)
	return Result{Edges: tr.edges()}, nil
}

// tinyParse reads a toy record: "FZ" magic, version byte, length byte, body.
// Each visit() marks a basic block, standing in for compiler instrumentation.
func tinyParse(t *tracer, in []byte) {
	t.visit(1)
	if len(in) < 4 {
		t.visit(2)
		return
	}
	if in[0] != 'F' {
		t.visit(3)
		return
	}
	t.visit(4)
	if in[1] != 'Z' {
		t.visit(5)
		return
	}
	t.visit(6)
	version := in[2]
	switch {
	case version == 1:
		t.visit(7)
	case version == 2:
		t.visit(8)
	case version >= 0x80:
		t.visit(9)
	default:
		t.visit(10)
		return
	}
	n := int(in[3])
	body := in[4:]
	if n == 0 {
		t.visit(11)
		return
	}
	t.visit(12)
	sum := 0
	for i := 0; i < n && i < len(body); i++ {
		sum += int(body[i])
	}
	if sum%7 == 3 {
		t.visit(13)
	} else {
		t.visit(14)
	}
	// Bug 1: version 2 trusts the declared length.
	if version == 2 && n > len(body) {
		t.visit(15)
		_ = body[n-1]
	}
	// Bug 2: extended records write into an index that was never allocated.
	if version >= 0x80 && len(body) >= 2 && body[0] == 0xde {
		t.visit(16)
		if body[1] == 0xad {
			t.visit(17)
			var index map[string]int
			index["record"]++
		}
	}
}

type tracer struct {
	hit []coverage.Edge
}

func (t *tracer) visit(e coverage.Edge) { t.hit = append(t.hit, e) }
func (t *tracer) edges() []coverage.Edge {
	return coverage.Normalize(t.hit)
}

// crashFromPanic classifies a recovered panic and records the target frames
// up to the harness boundary, so the signature does not depend on who called
// Execute (worker or coordinator) or on the input's concrete values.
func crashFromPanic(r any) *Crash {
	msg := fmt.Sprint(r)
	kind := "go-panic"
	switch {
	case strings.Contains(msg, "index out of range"), strings.Contains(msg, "slice bounds out of range"):
		kind = "go:index-out-of-range"
	case strings.Contains(msg, "nil map"):
		kind = "go:nil-map-write"
	case strings.Contains(msg, "nil pointer"):
		kind = "go:nil-dereference"
	}
	pcs := make([]uintptr, 64)
	n := runtime.Callers(1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var top []string
	for {
		f, more := frames.Next()
		fn := path.Base(f.Function)
		switch {
		case strings.HasPrefix(f.Function, "runtime."), strings.Contains(fn, "crashFromPanic"), strings.Contains(fn, "Execute.func"):
		case strings.HasSuffix(fn, "Execute"):
			more = false
		default:
			top = append(top, fmt.Sprintf("%s:%d", fn, f.Line))
		}
		if !more || len(top) == 3 {
			break
		}
	}
	return &Crash{Kind: kind, Signature: Signature(kind, top), Frames: slices.Clip(top)}
}
