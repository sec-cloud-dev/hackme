package coordinator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"fuzzpool/internal/identity"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/money"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
)

type fixture struct {
	t     *testing.T
	led   *ledger.Ledger
	c     *Coordinator
	camp  string
	clock time.Time
	nonce map[identity.WorkerID]uint64
}

var (
	priceEdge  = money.MustParse("0.5")
	priceCrash = money.MustParse("20")
)

func newFixture(t *testing.T, budget string) *fixture {
	t.Helper()
	f := &fixture{t: t, led: ledger.New(), clock: time.Unix(1_800_000_000, 0), nonce: map[identity.WorkerID]uint64{}}
	f.c = New(DefaultConfig(), f.led)
	f.c.SetClock(func() time.Time { return f.clock })
	must(t, f.led.Deposit("customer:acme", money.MustParse(budget), "card"))
	id, err := f.c.CreateCampaign(context.Background(), CampaignSpec{
		Name: "tinyparse", Customer: "customer:acme", Budget: money.MustParse(budget),
		PricePerEdge: priceEdge, PricePerCrash: priceCrash,
		Executor: target.TinyParse{}, Seeds: [][]byte{[]byte("FZ\x01\x00")},
	})
	must(t, err)
	f.camp = id
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) worker(stake string) *identity.Signer {
	f.t.Helper()
	s, err := identity.GenerateSigner()
	must(f.t, err)
	pub := s.PublicKey()
	_, err = f.c.Register(protocol.RegisterRequest{PublicKey: pub, Sig: s.Sign(protocol.DomainRegister, pub)})
	must(f.t, err)
	if stake != "" {
		must(f.t, f.led.Deposit(StakeAccount(s.ID()), money.MustParse(stake), "stake"))
	}
	return s
}

func (f *fixture) next(s *identity.Signer) uint64 {
	f.nonce[s.ID()]++
	return f.nonce[s.ID()]
}

func (f *fixture) lease(s *identity.Signer) (protocol.Lease, error) {
	req := protocol.LeaseRequest{WorkerID: s.ID(), Nonce: f.next(s)}
	req.Sig = s.Sign(protocol.DomainLease, req.SigningBytes())
	return f.c.Lease(req)
}

func (f *fixture) signed(s *identity.Signer, leaseID string, inputs ...protocol.Input) protocol.Submission {
	sub := protocol.Submission{WorkerID: s.ID(), LeaseID: leaseID, Nonce: f.next(s), Inputs: inputs}
	sub.Sig = s.Sign(protocol.DomainSubmit, sub.SigningBytes())
	return sub
}

func (f *fixture) submit(s *identity.Signer, leaseID string, inputs ...protocol.Input) (protocol.SubmitResponse, error) {
	return f.c.Submit(context.Background(), f.signed(s, leaseID, inputs...))
}

func in(s string) protocol.Input    { return protocol.Input{Data: []byte(s)} }
func crash(s string) protocol.Input { return protocol.Input{Data: []byte(s), ClaimCrash: true} }

func (f *fixture) invariant() {
	f.t.Helper()
	must(f.t, f.led.CheckInvariant())
}

func TestFeeAndEscrowOnCreate(t *testing.T) {
	f := newFixture(t, "100")
	if got := f.led.Balance(ledger.Platform); got != money.MustParse("5") {
		t.Errorf("platform fee %s, want 5", got)
	}
	if got := f.led.Balance(EscrowAccount(f.camp)); got != money.MustParse("95") {
		t.Errorf("escrow %s, want 95", got)
	}
	st, _ := f.c.Campaign(f.camp)
	if st.BaselineEdges != 5 {
		t.Errorf("customer seed coverage %d, want 5 (free baseline)", st.BaselineEdges)
	}
	f.invariant()
}

func TestPaysExactlyForVerifiedNewEdges(t *testing.T) {
	f := newFixture(t, "100")
	w := f.worker("5")
	l, err := f.lease(w)
	must(t, err)
	// "FZ\x01\x01a" reaches blocks 12 and 14 beyond the seed's coverage.
	resp, err := f.submit(w, l.ID, in("FZ\x01\x01a"), in("FZ\x01\x00"))
	must(t, err)
	v := resp.Verdicts
	if v[0].Status != protocol.StatusNewCoverage || v[0].NewEdges != 2 || v[0].Paid != money.MustParse("1") {
		t.Errorf("new input: %+v", v[0])
	}
	if v[1].Status != protocol.StatusNoNewCoverage || v[1].Paid != 0 {
		t.Errorf("seed resubmitted and paid: %+v", v[1])
	}
	if got := f.led.Balance(WalletAccount(w.ID())); got != money.MustParse("1") {
		t.Errorf("wallet %s", got)
	}
	f.invariant()
}

func TestStolenOrRepeatedInputsEarnNothing(t *testing.T) {
	f := newFixture(t, "100")
	honest, thief := f.worker("5"), f.worker("5")
	l1, _ := f.lease(honest)
	_, err := f.submit(honest, l1.ID, in("FZ\x01\x01a"))
	must(t, err)
	l2, _ := f.lease(thief)
	resp, err := f.submit(thief, l2.ID, in("FZ\x01\x01a"))
	must(t, err)
	if resp.Paid != 0 || resp.Verdicts[0].Status != protocol.StatusNoNewCoverage {
		t.Fatalf("thief paid for someone else's coverage: %+v", resp)
	}
}

func TestCrashPaidOncePerSignature(t *testing.T) {
	f := newFixture(t, "100")
	a, b := f.worker("5"), f.worker("5")
	la, _ := f.lease(a)
	resp, err := f.submit(a, la.ID, crash("FZ\x02\x05ab"))
	must(t, err)
	if v := resp.Verdicts[0]; v.Status != protocol.StatusNewCrash || v.Paid != priceCrash || v.CrashKind != "go:index-out-of-range" {
		t.Fatalf("first crash: %+v", v)
	}
	lb, _ := f.lease(b)
	resp, err = f.submit(b, lb.ID, crash("FZ\x02\x09xyz")) // same bug, different bytes
	must(t, err)
	if v := resp.Verdicts[0]; v.Status != protocol.StatusKnownCrash || v.Paid != 0 || v.Slashed != 0 {
		t.Fatalf("duplicate crash: %+v", v)
	}
	st, _ := f.c.Campaign(f.camp)
	if len(st.Crashes) != 1 || st.Crashes[0].FoundBy != a.ID() {
		t.Fatalf("crash records: %+v", st.Crashes)
	}
	repro, err := f.c.Reproducer(f.camp, st.Crashes[0].Signature)
	if err != nil || string(repro) != "FZ\x02\x05ab" {
		t.Fatalf("reproducer %q %v", repro, err)
	}
	f.invariant()
}

func TestFalseCrashClaimIsSlashed(t *testing.T) {
	f := newFixture(t, "100")
	w := f.worker("5")
	l, _ := f.lease(w)
	resp, err := f.submit(w, l.ID, crash("FZ\x01\x00"), crash("AAAA"))
	must(t, err)
	for _, v := range resp.Verdicts {
		if v.Status != protocol.StatusFalseCrash || v.Paid != 0 || v.Slashed != money.MustParse("1") {
			t.Errorf("false claim: %+v", v)
		}
	}
	if got := f.led.Balance(StakeAccount(w.ID())); got != money.MustParse("3") {
		t.Errorf("stake after two slashes %s, want 3", got)
	}
	if got := f.led.Balance(EscrowAccount(f.camp)); got != money.MustParse("97") {
		t.Errorf("slash should compensate escrow: %s", got)
	}
	// Stake now below the minimum: no more leases until topped up.
	if _, err := f.lease(w); !errors.Is(err, ErrNoStake) {
		t.Errorf("lease with depleted stake: %v", err)
	}
	f.invariant()
}

func TestAuthenticationAndReplay(t *testing.T) {
	f := newFixture(t, "100")
	honest, attacker := f.worker("5"), f.worker("5")
	l, _ := f.lease(honest)

	sub := f.signed(honest, l.ID, in("FZ\x01\x01a"))
	if _, err := f.c.Submit(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Submit(context.Background(), sub); !errors.Is(err, ErrStaleNonce) {
		t.Errorf("replayed submission: %v", err)
	}

	forged := protocol.Submission{WorkerID: honest.ID(), LeaseID: l.ID, Nonce: 1 << 40, Inputs: []protocol.Input{in("FZ\x80\x01a")}}
	forged.Sig = attacker.Sign(protocol.DomainSubmit, forged.SigningBytes())
	if _, err := f.c.Submit(context.Background(), forged); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged signature: %v", err)
	}

	// A lease signature cannot be reused as a submission signature.
	lr := protocol.LeaseRequest{WorkerID: honest.ID(), Nonce: 1 << 41}
	cross := protocol.Submission{WorkerID: honest.ID(), LeaseID: l.ID, Nonce: 1 << 41, Inputs: []protocol.Input{in("x")}}
	cross.Sig = honest.Sign(protocol.DomainLease, lr.SigningBytes())
	if _, err := f.c.Submit(context.Background(), cross); !errors.Is(err, ErrBadSignature) {
		t.Errorf("cross-domain signature: %v", err)
	}

	if _, err := f.submit(attacker, l.ID, in("FZ\x80\x01a")); !errors.Is(err, ErrLeaseOwner) {
		t.Errorf("using someone else's lease: %v", err)
	}
	f.invariant()
}

func TestLeaseLifecycleAndLimits(t *testing.T) {
	f := newFixture(t, "100")
	if _, err := f.lease(f.worker("")); !errors.Is(err, ErrNoStake) {
		t.Errorf("unstaked worker leased: %v", err)
	}
	w := f.worker("5")
	l, _ := f.lease(w)
	big := protocol.Input{Data: make([]byte, f.c.cfg.MaxInputBytes+1)}
	if _, err := f.submit(w, l.ID, big); !errors.Is(err, ErrLimits) {
		t.Errorf("oversized input: %v", err)
	}
	many := make([]protocol.Input, f.c.cfg.MaxInputsPerSubmission+1)
	if _, err := f.submit(w, l.ID, many...); !errors.Is(err, ErrLimits) {
		t.Errorf("too many inputs: %v", err)
	}
	for i := 1; i < f.c.cfg.MaxLeasesPerWorker; i++ {
		if _, err := f.lease(w); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.lease(w); !errors.Is(err, ErrLeaseExhausted) {
		t.Errorf("lease hoarding: %v", err)
	}
	f.clock = f.clock.Add(f.c.cfg.LeaseTTL + f.c.cfg.LeaseGrace + time.Second)
	if _, err := f.submit(w, l.ID, in("FZ\x01\x01a")); !errors.Is(err, ErrLeaseExpired) {
		t.Errorf("expired lease: %v", err)
	}
	if _, err := f.lease(w); err != nil {
		t.Errorf("expired leases still counted: %v", err)
	}
}

func TestEscrowCapsPayoutsAndClosesCampaign(t *testing.T) {
	f := newFixture(t, "2") // 1.9 in escrow after the 5% fee
	w := f.worker("5")
	l, _ := f.lease(w)
	resp, err := f.submit(w, l.ID, in("FZ\x01\x01a"), in("FZ\x80\x01a"), in("AAAA"))
	must(t, err)
	if resp.Paid != money.MustParse("1.9") || resp.EscrowRemaining != 0 || resp.CampaignOpen {
		t.Fatalf("escrow overrun or campaign left open: %+v", resp)
	}
	if _, err := f.submit(w, l.ID, in("FZ\x02\x01a")); !errors.Is(err, ErrCampaignClosed) {
		t.Errorf("submission to closed campaign: %v", err)
	}
	if _, err := f.lease(w); !errors.Is(err, ErrNoWork) {
		t.Errorf("lease on drained campaign: %v", err)
	}
	f.invariant()
}

// Concurrent workers racing for the same edges: each edge is paid once and
// total payouts equal escrow decrease.
func TestConcurrentSubmissionsPayEachEdgeOnce(t *testing.T) {
	f := newFixture(t, "1000")
	inputs := []protocol.Input{in("FZ\x01\x01a"), in("FZ\x02\x01a"), in("FZ\x80\x01a"), in("FZ\x80\x02\xde\x00"), in("FZ\x03\x00\x00")}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var subs []protocol.Submission
	for i := 0; i < 8; i++ {
		w := f.worker("5")
		l, err := f.lease(w)
		must(t, err)
		subs = append(subs, f.signed(w, l.ID, inputs...))
	}
	total := money.Amount(0)
	for _, s := range subs {
		wg.Add(1)
		go func(s protocol.Submission) {
			defer wg.Done()
			resp, err := f.c.Submit(context.Background(), s)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			total += resp.Paid
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	st, _ := f.c.Campaign(f.camp)
	wantEdges := st.Edges - st.BaselineEdges
	want, _ := priceEdge.MulInt(int64(wantEdges))
	if total != want || st.PaidOut != want {
		t.Fatalf("paid %s (stats %s) for %d new edges, want %s", total, st.PaidOut, wantEdges, want)
	}
	f.invariant()
}
