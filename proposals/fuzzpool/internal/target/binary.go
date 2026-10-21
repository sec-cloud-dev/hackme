package target

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"fuzzpool/internal/sandbox"
)

// Binary replays inputs against a real fuzz target built with sanitizers,
// e.g. `afl-clang-fast -fsanitize=address,fuzzer harness.c -o target`.
// Such a binary runs each file argument once (libFuzzer driver) and is also
// AFL-instrumented, so afl-showmap can measure exactly which edges an input
// reached. Both runs happen inside the sandbox.
type Binary struct {
	Path        string
	ShowmapPath string // afl-showmap; empty means crash-only verification
	Timeout     time.Duration
	Runner      sandbox.Runner
	digest      string
}

// OpenBinary hashes the target so campaigns can pin the exact build.
func OpenBinary(path, showmap string, timeout time.Duration, runner sandbox.Runner) (*Binary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = sandbox.Direct{}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Binary{
		Path: abs, ShowmapPath: showmap, Timeout: timeout, Runner: runner,
		digest: "sha256:" + hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func (b *Binary) Digest() string { return b.digest }

func (b *Binary) Execute(ctx context.Context, input []byte) (Result, error) {
	dir, err := os.MkdirTemp("", "fuzzpool-exec-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	in := filepath.Join(dir, "input")
	if err := os.WriteFile(in, input, 0o600); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()

	ro := []string{b.Path}
	stderr := &capped{max: 1 << 20}
	cmd := b.Runner.Command(ctx, sandbox.Spec{Workdir: dir, ReadOnly: ro, Argv: []string{b.Path, in}})
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	runErr := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Result{Crash: &Crash{Kind: "timeout", Signature: Signature("timeout", nil)}}, nil
	}
	if crash := ParseSanitizerReport(stderr.Bytes()); crash != nil {
		return Result{Crash: crash}, nil
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return Result{}, fmt.Errorf("target: run: %w", runErr)
	}
	if runErr != nil {
		// Non-zero exit without a sanitizer report: not a payable crash, and
		// possibly a broken sandbox. Surface it as a verifier error.
		return Result{}, fmt.Errorf("target: exited %d without a sanitizer report", exitErr.ExitCode())
	}
	if b.ShowmapPath == "" {
		return Result{}, nil
	}

	mapFile := filepath.Join(dir, "map")
	ms := strconv.FormatInt(b.Timeout.Milliseconds(), 10)
	cmd = b.Runner.Command(ctx, sandbox.Spec{
		Workdir:  dir,
		ReadOnly: append(ro, b.ShowmapPath),
		Env:      []string{"AFL_QUIET=1"},
		Argv:     []string{b.ShowmapPath, "-q", "-e", "-t", ms, "-o", mapFile, "--", b.Path, in},
	})
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	_ = cmd.Run() // afl-showmap's exit code reflects the target; the map is what matters
	data, err := os.ReadFile(mapFile)
	if err != nil {
		return Result{}, fmt.Errorf("target: afl-showmap produced no map: %w", err)
	}
	edges, err := ParseShowmap(data)
	if err != nil {
		return Result{}, err
	}
	return Result{Edges: edges}, nil
}

// capped keeps the first max bytes of output and drops the rest, so a target
// spamming stderr cannot exhaust the verifier's memory.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capped) Bytes() []byte { return c.buf.Bytes() }
