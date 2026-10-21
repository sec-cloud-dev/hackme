// Command worker leases campaigns from a coordinator and fuzzes them.
//
//	worker -coordinator http://127.0.0.1:8090 -engine libfuzzer -binary ./target
//	worker -coordinator http://127.0.0.1:8090 -engine aflpp -binary ./target
//	worker -coordinator http://127.0.0.1:8090 -engine demo
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"fuzzpool/internal/coordinator"
	"fuzzpool/internal/identity"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/sandbox"
	"fuzzpool/internal/target"
	"fuzzpool/internal/worker"
)

func main() {
	url := flag.String("coordinator", "http://127.0.0.1:8090", "coordinator base URL")
	keyPath := flag.String("key", "worker.key", "Ed25519 seed file (hex); created if missing")
	engine := flag.String("engine", "demo", "demo, libfuzzer or aflpp")
	bin := flag.String("binary", "", "fuzz target for libfuzzer/aflpp")
	aflFuzz := flag.String("afl-fuzz", "", "afl-fuzz path (default: from PATH)")
	sb := flag.String("sandbox", "bwrap", "bwrap, or none (trusted targets only)")
	duration := flag.Duration("duration", time.Minute, "fuzzing time per lease (libfuzzer/aflpp)")
	iterations := flag.Int("iterations", 1_000_000, "mutations per lease (demo engine)")
	rounds := flag.Int("rounds", 0, "number of leases to work; 0 = until interrupted")
	flag.Parse()

	signer, err := loadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	var runner sandbox.Runner = sandbox.Bwrap{}
	if *sb == "none" {
		runner = sandbox.Direct{}
	}

	var eng worker.Engine
	switch *engine {
	case "demo":
		eng = &worker.MutationEngine{Exec: target.TinyParse{}, Iterations: *iterations, MaxInputs: 256}
	case "libfuzzer", "aflpp":
		if *bin == "" {
			log.Fatal("-binary is required for this engine")
		}
		b, err := target.OpenBinary(*bin, "", 0, nil)
		if err != nil {
			log.Fatal(err)
		}
		if *engine == "libfuzzer" {
			eng = &worker.LibFuzzerEngine{Binary: b.Path, Digest: b.Digest(), Runner: runner, Duration: *duration, MaxInputs: 256}
		} else {
			path := *aflFuzz
			if path == "" {
				if path, err = exec.LookPath("afl-fuzz"); err != nil {
					log.Fatal("afl-fuzz not found; pass -afl-fuzz")
				}
			}
			eng = &worker.AFLPlusPlusEngine{AFLFuzz: path, Binary: b.Path, Digest: b.Digest(), Runner: runner, Duration: *duration, MaxInputs: 256}
		}
	default:
		log.Fatalf("unknown -engine %q", *engine)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &worker.Client{BaseURL: *url, Signer: signer}
	id, err := client.Register(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("worker %s registered; stake account to fund: %s", id, coordinator.StakeAccount(id))

	w := &worker.Worker{Client: client, Engine: eng}
	for i := 0; *rounds == 0 || i < *rounds; i++ {
		if ctx.Err() != nil {
			return
		}
		resp, err := w.Round(ctx)
		var apiErr *worker.APIError
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusPaymentRequired) {
			log.Printf("no lease: %s; retrying in 30s", apiErr.Message)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("round %d: %s paid=%s slashed=%s escrow_left=%s", i+1, summarize(resp.Verdicts), resp.Paid, resp.Slashed, resp.EscrowRemaining)
	}
}

func summarize(vs []protocol.Verdict) string {
	counts := map[string]int{}
	for _, v := range vs {
		counts[v.Status]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	if len(parts) == 0 {
		return "nothing new"
	}
	return strings.Join(parts, " ")
}

func loadOrCreateKey(path string) (*identity.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return identity.SignerFromSeed(seed)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	s, err := identity.GenerateSigner()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(s.Seed())+"\n"), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}
