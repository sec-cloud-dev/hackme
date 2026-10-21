package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fuzzpool/internal/coordinator"
	"fuzzpool/internal/identity"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/money"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
)

func TestMutationEngineFindsBothPlantedBugs(t *testing.T) {
	e := &MutationEngine{Exec: target.TinyParse{}, Iterations: 1_500_000, MaxInputs: 1000, Rand: rand.New(rand.NewPCG(1, 2))}
	lease := protocol.Lease{TargetDigest: target.TinyParse{}.Digest(), Seeds: [][]byte{[]byte("FZ\x01\x00")}}
	inputs, err := e.Fuzz(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, in := range inputs {
		if in.ClaimCrash {
			res, _ := target.TinyParse{}.Execute(context.Background(), in.Data)
			kinds[res.Crash.Kind] = true
		}
	}
	if !kinds["go:index-out-of-range"] || !kinds["go:nil-map-write"] {
		t.Fatalf("crashes found: %v (from %d inputs)", kinds, len(inputs))
	}
}

func TestEngineRefusesWrongBuild(t *testing.T) {
	e := &MutationEngine{Exec: target.TinyParse{}, Iterations: 10, MaxInputs: 10}
	if _, err := e.Fuzz(context.Background(), protocol.Lease{TargetDigest: "sha256:other"}); err == nil {
		t.Fatal("fuzzed a lease for a different target build")
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A stand-in for libFuzzer: writes one new corpus file and one crash
// artifact, then exits 1 like libFuzzer does after a crash.
func TestLibFuzzerHarvest(t *testing.T) {
	bin := writeScript(t, `
for a in "$@"; do
  case "$a" in
    -artifact_prefix=*) prefix="${a#-artifact_prefix=}" ;;
    -*) ;;
    *) corpus="$a" ;;
  esac
done
printf 'new-coverage' > "$corpus/f00d"
printf 'boom' > "${prefix}crash-deadbeef"
printf 'slow' > "${prefix}timeout-1"
exit 1
`)
	e := &LibFuzzerEngine{Binary: bin, Digest: "lf", Duration: time.Second, MaxInputs: 10}
	lease := protocol.Lease{TargetDigest: "afl", Seeds: [][]byte{[]byte("seed")}}
	if _, err := e.Fuzz(context.Background(), lease); err == nil {
		t.Fatal("libFuzzer build not pinned by the campaign was accepted")
	}
	lease.Builds = map[string]string{"libfuzzer": "lf"}
	inputs, err := e.Fuzz(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || string(inputs[0].Data) != "boom" || !inputs[0].ClaimCrash ||
		string(inputs[1].Data) != "new-coverage" || inputs[1].ClaimCrash {
		t.Fatalf("harvested %+v", inputs)
	}
}

func TestAFLPlusPlusHarvest(t *testing.T) {
	afl := writeScript(t, `
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; esac; shift; done
mkdir -p "$out/default/queue" "$out/default/crashes"
printf 'seed' > "$out/default/queue/id:000000,time:0,execs:0,orig:seed-00000"
printf 'q1' > "$out/default/queue/id:000001,src:000000,op:havoc"
printf 'c1' > "$out/default/crashes/id:000000,sig:06,src:000001"
printf 'x' > "$out/default/crashes/README.txt"
`)
	e := &AFLPlusPlusEngine{AFLFuzz: afl, Binary: "/bin/true", Digest: "d", Duration: time.Second, MaxInputs: 10}
	inputs, err := e.Fuzz(context.Background(), protocol.Lease{TargetDigest: "d", Seeds: [][]byte{[]byte("seed")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || string(inputs[0].Data) != "c1" || !inputs[0].ClaimCrash || string(inputs[1].Data) != "q1" {
		t.Fatalf("harvested %+v", inputs)
	}
}

// End to end over real HTTP: an honest worker earns, every cheat fails.
func TestEndToEndHTTP(t *testing.T) {
	led := ledger.New()
	coord := coordinator.New(coordinator.DefaultConfig(), led)
	srv := &coordinator.Server{Coord: coord, Ledger: led, AdminToken: "t0ken",
		Targets: map[string]target.Executor{"tinyparse": target.TinyParse{}}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx := context.Background()

	admin := &Client{BaseURL: ts.URL}
	adminDo := func(path string, in, out any) error {
		b, _ := json.Marshal(in)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer t0ken")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return &APIError{Status: resp.StatusCode}
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}

	if err := adminDo("/v1/admin/deposits", map[string]any{"account": "customer:acme", "amount": "100"}, nil); err != nil {
		t.Fatal(err)
	}
	var camp coordinator.CampaignStats
	if err := adminDo("/v1/admin/campaigns", map[string]any{
		"name": "tinyparse", "customer": "customer:acme", "budget": "100",
		"price_per_edge": "0.5", "price_per_crash": "20", "target": "tinyparse",
		"seeds": [][]byte{[]byte("FZ\x01\x00")},
	}, &camp); err != nil {
		t.Fatal(err)
	}

	newClient := func() *Client {
		s, _ := identity.GenerateSigner()
		c := &Client{BaseURL: ts.URL, Signer: s}
		if _, err := c.Register(ctx); err != nil {
			t.Fatal(err)
		}
		if err := adminDo("/v1/admin/deposits", map[string]any{"account": coordinator.StakeAccount(s.ID()), "amount": "5"}, nil); err != nil {
			t.Fatal(err)
		}
		return c
	}
	honest, cheater := newClient(), newClient()

	w := &Worker{Client: honest, Engine: &MutationEngine{Exec: target.TinyParse{}, Iterations: 300_000, MaxInputs: 500, Rand: rand.New(rand.NewPCG(3, 4))}}
	resp, err := w.Round(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Paid <= 0 || resp.Slashed != 0 {
		t.Fatalf("honest round: paid %s slashed %s", resp.Paid, resp.Slashed)
	}

	// Cheat 1: claim a hashrate. The field does not exist and is rejected.
	l, err := cheater.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"worker_id":"` + string(cheater.Signer.ID()) + `","lease_id":"` + l.ID + `","nonce":1,"inputs":[],"hashrate_gh_s":1700}`)
	var apiErr *APIError
	if err := cheater.Do(ctx, http.MethodPost, "/v1/submissions", raw, nil); !errors.As(err, &apiErr) || apiErr.Status != 400 {
		t.Fatalf("hashrate claim: %v", err)
	}
	// Cheat 2: resubmit the honest worker's corpus (shared as lease seeds).
	var stolen []protocol.Input
	for _, s := range l.Seeds {
		stolen = append(stolen, protocol.Input{Data: s})
	}
	r2, err := cheater.Submit(ctx, l.ID, stolen)
	if err != nil || r2.Paid != 0 {
		t.Fatalf("stolen corpus: paid %s, %v", r2.Paid, err)
	}
	// Cheat 3: replay a captured signed submission.
	sub := cheater.NewSubmission(l.ID, []protocol.Input{{Data: []byte("x")}})
	if _, err := cheater.Send(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := cheater.Send(ctx, sub); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("replay: %v", err)
	}
	// Cheat 4: fake crash claim costs stake.
	r4, err := cheater.Submit(ctx, l.ID, []protocol.Input{{Data: []byte("AAAA"), ClaimCrash: true}})
	if err != nil || r4.Slashed != money.Unit {
		t.Fatalf("fake crash: %+v %v", r4, err)
	}

	var inv map[string]any
	if err := admin.Do(ctx, http.MethodGet, "/v1/ledger/invariant", nil, &inv); err != nil || inv["ok"] != true {
		t.Fatalf("ledger invariant: %v %v", inv, err)
	}
}
