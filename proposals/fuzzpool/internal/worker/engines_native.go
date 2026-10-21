package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fuzzpool/internal/protocol"
	"fuzzpool/internal/sandbox"
)

// LibFuzzerEngine runs a real libFuzzer binary inside the sandbox and hands
// back everything it kept: new corpus files as coverage candidates and
// crash-*/leak-* artifacts as crash claims. It judges nothing itself.
type LibFuzzerEngine struct {
	Binary    string
	Digest    string // sha256 of Binary, must match the lease
	Runner    sandbox.Runner
	Duration  time.Duration
	MaxInputs int
}

func (e *LibFuzzerEngine) Fuzz(ctx context.Context, lease protocol.Lease) ([]protocol.Input, error) {
	if err := checkDigest(lease, "libfuzzer", e.Digest); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "fuzzpool-libfuzzer-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	corpus, crashes := filepath.Join(dir, "corpus"), filepath.Join(dir, "crashes")
	for _, d := range []string{corpus, crashes} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, err
		}
	}
	known, err := writeSeeds(corpus, lease.Seeds)
	if err != nil {
		return nil, err
	}
	secs := max(1, int(e.Duration.Seconds()))
	argv := []string{e.Binary,
		"-max_total_time=" + strconv.Itoa(secs),
		"-artifact_prefix=" + crashes + "/",
		"-close_fd_mask=3",
		corpus,
	}
	if err := runEngine(ctx, e.Runner, sandbox.Spec{Workdir: dir, ReadOnly: []string{e.Binary}, Argv: argv}, e.Duration); err != nil {
		return nil, err
	}
	crashIn, err := harvest(crashes, func(n string) bool {
		return strings.HasPrefix(n, "crash-") || strings.HasPrefix(n, "leak-")
	}, known, true)
	if err != nil {
		return nil, err
	}
	covIn, err := harvest(corpus, func(string) bool { return true }, known, false)
	if err != nil {
		return nil, err
	}
	return limitInputs(append(crashIn, covIn...), e.MaxInputs), nil
}

// AFLPlusPlusEngine runs afl-fuzz for a fixed time and harvests its queue
// and crashes directories.
type AFLPlusPlusEngine struct {
	AFLFuzz   string // path to afl-fuzz
	Binary    string
	Digest    string
	Runner    sandbox.Runner
	Duration  time.Duration
	MaxInputs int
}

func (e *AFLPlusPlusEngine) Fuzz(ctx context.Context, lease protocol.Lease) ([]protocol.Input, error) {
	if err := checkDigest(lease, "aflpp", e.Digest); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "fuzzpool-aflpp-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inDir, outDir := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.Mkdir(inDir, 0o700); err != nil {
		return nil, err
	}
	seeds := lease.Seeds
	if len(seeds) == 0 {
		seeds = [][]byte{{0}} // afl-fuzz refuses an empty input directory
	}
	known, err := writeSeeds(inDir, seeds)
	if err != nil {
		return nil, err
	}
	secs := max(1, int(e.Duration.Seconds()))
	spec := sandbox.Spec{
		Workdir:  dir,
		ReadOnly: []string{e.AFLFuzz, e.Binary},
		Env:      []string{"AFL_NO_UI=1", "AFL_SKIP_CPUFREQ=1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"},
		Argv:     []string{e.AFLFuzz, "-i", inDir, "-o", outDir, "-V", strconv.Itoa(secs), "--", e.Binary, "@@"},
	}
	if err := runEngine(ctx, e.Runner, spec, e.Duration); err != nil {
		return nil, err
	}
	base := filepath.Join(outDir, "default")
	crashIn, err := harvest(filepath.Join(base, "crashes"), func(n string) bool { return strings.HasPrefix(n, "id:") }, known, true)
	if err != nil {
		return nil, err
	}
	covIn, err := harvest(filepath.Join(base, "queue"), func(n string) bool {
		return strings.HasPrefix(n, "id:") && !strings.Contains(n, ",orig:")
	}, known, false)
	if err != nil {
		return nil, err
	}
	return limitInputs(append(crashIn, covIn...), e.MaxInputs), nil
}

func runEngine(ctx context.Context, r sandbox.Runner, spec sandbox.Spec, d time.Duration) error {
	if r == nil {
		r = sandbox.Direct{}
	}
	ctx, cancel := context.WithTimeout(ctx, d+30*time.Second)
	defer cancel()
	cmd := r.Command(ctx, spec)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err := cmd.Run()
	// Fuzzers exit non-zero after finding a crash; that is the good case.
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return fmt.Errorf("worker: start %s: %w", spec.Argv[0], err)
	}
	return nil
}

// limitInputs keeps crashes first (they come first) and caps the batch.
func limitInputs(in []protocol.Input, n int) []protocol.Input {
	if n > 0 && len(in) > n {
		return in[:n]
	}
	return in
}
