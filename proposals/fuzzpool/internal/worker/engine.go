package worker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"fuzzpool/internal/coverage"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
)

// Engine produces candidate inputs for a lease. It only proposes; the
// coordinator decides what each input is worth by replaying it.
type Engine interface {
	Fuzz(ctx context.Context, lease protocol.Lease) ([]protocol.Input, error)
}

// checkDigest refuses to fuzz a build other than the one the campaign pins
// for this engine; engines without their own entry use the verifier build.
func checkDigest(lease protocol.Lease, engine, digest string) error {
	want := lease.Builds[engine]
	if want == "" {
		want = lease.TargetDigest
	}
	if want != digest {
		return fmt.Errorf("worker: campaign pins %s build %s, this engine runs %s", engine, want, digest)
	}
	return nil
}

// MutationEngine is a small coverage-guided mutational fuzzer for in-process
// executors. It exists so the demo runs anywhere; production workers use
// LibFuzzerEngine or AFLPlusPlusEngine.
type MutationEngine struct {
	Exec       target.Executor
	Iterations int
	MaxInputs  int
	MaxLen     int
	Rand       *rand.Rand
}

func (e *MutationEngine) Fuzz(ctx context.Context, lease protocol.Lease) ([]protocol.Input, error) {
	if err := checkDigest(lease, "demo", e.Exec.Digest()); err != nil {
		return nil, err
	}
	r := e.Rand
	if r == nil {
		r = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	maxLen := e.MaxLen
	if maxLen <= 0 {
		maxLen = 64
	}
	corpus := slices.Clone(lease.Seeds)
	if len(corpus) == 0 {
		corpus = [][]byte{{}}
	}
	local := coverage.NewMap()
	for _, s := range corpus {
		res, err := e.Exec.Execute(ctx, s)
		if err != nil {
			return nil, err
		}
		local.Add(res.Edges)
	}
	seenCrash := map[string]bool{}
	var out []protocol.Input
	for i := 0; i < e.Iterations && len(out) < e.MaxInputs; i++ {
		if ctx.Err() != nil {
			break
		}
		child := mutate(r, corpus[r.IntN(len(corpus))], corpus, maxLen)
		res, err := e.Exec.Execute(ctx, child)
		if err != nil {
			return out, err
		}
		if res.Crash != nil {
			if !seenCrash[res.Crash.Signature] {
				seenCrash[res.Crash.Signature] = true
				out = append(out, protocol.Input{Data: child, ClaimCrash: true})
			}
			continue
		}
		if local.Add(res.Edges) > 0 {
			corpus = append(corpus, child)
			out = append(out, protocol.Input{Data: child})
		}
	}
	return out, nil
}

var interesting = []byte{0, 1, 2, 0x7f, 0x80, 0xff}

func mutate(r *rand.Rand, parent []byte, corpus [][]byte, maxLen int) []byte {
	child := slices.Clone(parent)
	for n := 1 + r.IntN(4); n > 0; n-- {
		switch r.IntN(7) {
		case 0:
			if len(child) > 0 {
				child[r.IntN(len(child))] ^= 1 << r.IntN(8)
			}
		case 1:
			if len(child) > 0 {
				child[r.IntN(len(child))] = byte(r.IntN(256))
			}
		case 2:
			if len(child) > 0 {
				child[r.IntN(len(child))] = interesting[r.IntN(len(interesting))]
			}
		case 3:
			if len(child) < maxLen {
				child = slices.Insert(child, r.IntN(len(child)+1), byte(r.IntN(256)))
			}
		case 4:
			if len(child) > 0 {
				i := r.IntN(len(child))
				child = slices.Delete(child, i, i+1)
			}
		case 5:
			if len(child) > 0 {
				child[r.IntN(len(child))] += byte(r.IntN(35)) - 17
			}
		case 6:
			other := corpus[r.IntN(len(corpus))]
			if len(other) > 0 {
				at := r.IntN(len(child) + 1)
				child = append(child[:at:at], other[r.IntN(len(other)):]...)
			}
		}
	}
	if len(child) > maxLen {
		child = child[:maxLen]
	}
	return child
}

// writeSeeds stores the lease corpus as files and returns their hashes so
// harvesting can skip inputs the coordinator already has.
func writeSeeds(dir string, seeds [][]byte) (map[[32]byte]bool, error) {
	known := make(map[[32]byte]bool, len(seeds))
	for i, s := range seeds {
		known[sha256.Sum256(s)] = true
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed-%05d", i)), s, 0o600); err != nil {
			return nil, err
		}
	}
	return known, nil
}

// harvest reads engine output files in name order, skipping known inputs
// and duplicates.
func harvest(dir string, keep func(name string) bool, known map[[32]byte]bool, claimCrash bool) ([]protocol.Input, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []protocol.Input
	for _, e := range entries {
		if !e.Type().IsRegular() || !keep(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(data)
		if known[h] {
			continue
		}
		known[h] = true
		out = append(out, protocol.Input{Data: data, ClaimCrash: claimCrash})
	}
	return out, nil
}
