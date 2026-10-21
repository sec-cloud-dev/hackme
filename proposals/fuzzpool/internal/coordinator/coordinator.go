// Package coordinator runs fuzzing campaigns and pays workers strictly for
// results it has verified itself:
//
//   - new coverage, measured by replaying the input against the pinned target;
//   - new crashes, reproduced twice with the same signature.
//
// Nothing a worker reports about itself is ever paid for: there is no
// hashrate, no attempt count and no "time spent". Money is never created
// here either; every payout comes out of escrow a customer funded.
package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"sort"
	"sync"
	"time"

	"fuzzpool/internal/coverage"
	"fuzzpool/internal/identity"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/money"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
)

type Config struct {
	LeaseTTL               time.Duration
	LeaseGrace             time.Duration // late submissions still accepted after expiry
	ExecTimeout            time.Duration // per replay of one input
	MaxInputsPerSubmission int
	MaxInputBytes          int
	MaxSubmissionsPerLease int
	MaxLeasesPerWorker     int // live leases per worker; bounds verifier load one stake can cause
	SeedsPerLease          int
	MinStake               money.Amount // needed to lease; makes Sybil spam cost money
	FalseCrashPenalty      money.Amount // taken from stake per crash claim that does not reproduce
	PlatformFeeBps         int64        // disclosed fee, taken once when a campaign is funded
}

func DefaultConfig() Config {
	return Config{
		LeaseTTL:               10 * time.Minute,
		LeaseGrace:             2 * time.Minute,
		ExecTimeout:            5 * time.Second,
		MaxInputsPerSubmission: 64,
		MaxInputBytes:          1 << 20,
		MaxSubmissionsPerLease: 16,
		MaxLeasesPerWorker:     4,
		SeedsPerLease:          32,
		MinStake:               5 * money.Unit,
		FalseCrashPenalty:      1 * money.Unit,
		PlatformFeeBps:         500,
	}
}

var (
	ErrUnknownWorker   = errors.New("coordinator: unknown worker")
	ErrBadSignature    = errors.New("coordinator: bad signature")
	ErrStaleNonce      = errors.New("coordinator: stale nonce (replayed request)")
	ErrNoStake         = errors.New("coordinator: stake below minimum")
	ErrNoWork          = errors.New("coordinator: no open campaign")
	ErrUnknownLease    = errors.New("coordinator: unknown lease")
	ErrLeaseOwner      = errors.New("coordinator: lease belongs to another worker")
	ErrLeaseExpired    = errors.New("coordinator: lease expired")
	ErrLeaseExhausted  = errors.New("coordinator: too many submissions for this lease")
	ErrCampaignClosed  = errors.New("coordinator: campaign closed")
	ErrUnknownCampaign = errors.New("coordinator: unknown campaign")
	ErrLimits          = errors.New("coordinator: submission exceeds limits")
	ErrInvalidSpec     = errors.New("coordinator: invalid campaign spec")
)

// Accounts. Worker money is split: the wallet holds earnings, the stake is
// collateral that false claims burn into the customer's escrow.
func WalletAccount(id identity.WorkerID) ledger.Account { return ledger.Account("worker:" + id) }
func StakeAccount(id identity.WorkerID) ledger.Account  { return ledger.Account("stake:" + id) }
func EscrowAccount(campaignID string) ledger.Account    { return ledger.Account("escrow:" + campaignID) }

type CampaignSpec struct {
	Name          string
	Customer      ledger.Account
	Budget        money.Amount
	PricePerEdge  money.Amount
	PricePerCrash money.Amount
	Executor      target.Executor
	Builds        map[string]string // engine -> sha256 of the worker build, e.g. "libfuzzer"
	Seeds         [][]byte          // the customer's existing corpus; its coverage is free
}

type CrashRecord struct {
	Signature string            `json:"signature"`
	Kind      string            `json:"kind"`
	Frames    []string          `json:"frames"`
	FoundBy   identity.WorkerID `json:"found_by"`
	FoundAt   time.Time         `json:"found_at"`
	Paid      money.Amount      `json:"paid"`
	input     []byte
}

type CampaignStats struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	TargetDigest    string        `json:"target_digest"`
	Open            bool          `json:"open"`
	EscrowRemaining money.Amount  `json:"escrow_remaining"`
	PaidOut         money.Amount  `json:"paid_out"`
	BaselineEdges   int           `json:"baseline_edges"`
	Edges           int           `json:"edges"`
	CorpusSize      int           `json:"corpus_size"`
	Crashes         []CrashRecord `json:"crashes"`
}

type WorkerStats struct {
	ID       identity.WorkerID `json:"id"`
	Wallet   money.Amount      `json:"wallet"`
	Stake    money.Amount      `json:"stake"`
	Earned   money.Amount      `json:"earned"`
	Slashed  money.Amount      `json:"slashed"`
	Verdicts map[string]int    `json:"verdicts"`
}

type campaign struct {
	id, name      string
	customer      ledger.Account
	exec          target.Executor
	builds        map[string]string
	pricePerEdge  money.Amount
	pricePerCrash money.Amount
	baseline      int
	cov           *coverage.Map
	corpus        [][]byte
	corpusSeen    map[[32]byte]bool
	crashes       map[string]*CrashRecord
	crashOrder    []string
	paid          money.Amount
	open          bool
}

type workerState struct {
	id        identity.WorkerID
	pub       ed25519.PublicKey
	lastNonce uint64
	earned    money.Amount
	slashed   money.Amount
	verdicts  map[string]int
}

type leaseState struct {
	lease       protocol.Lease
	worker      identity.WorkerID
	submissions int
}

type Coordinator struct {
	cfg Config
	led *ledger.Ledger
	now func() time.Time

	mu        sync.Mutex
	workers   map[identity.WorkerID]*workerState
	campaigns map[string]*campaign
	order     []string
	cursor    int
	leases    map[string]*leaseState
}

func New(cfg Config, led *ledger.Ledger) *Coordinator {
	return &Coordinator{
		cfg: cfg, led: led, now: time.Now,
		workers:   make(map[identity.WorkerID]*workerState),
		campaigns: make(map[string]*campaign),
		leases:    make(map[string]*leaseState),
	}
}

// SetClock replaces the time source (tests).
func (c *Coordinator) SetClock(now func() time.Time) { c.now = now }

func (c *Coordinator) Config() Config { return c.cfg }

// Register adds a worker after it proves it holds the private key.
func (c *Coordinator) Register(req protocol.RegisterRequest) (identity.WorkerID, error) {
	pub := ed25519.PublicKey(req.PublicKey)
	if len(pub) != ed25519.PublicKeySize || !identity.Verify(pub, protocol.DomainRegister, req.PublicKey, req.Sig) {
		return "", ErrBadSignature
	}
	id := identity.IDFromPublicKey(pub)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.workers[id]; !ok {
		c.workers[id] = &workerState{id: id, pub: pub, verdicts: make(map[string]int)}
	}
	return id, nil
}

// CreateCampaign moves the budget from the customer into escrow, minus the
// disclosed platform fee. The customer's seed corpus is replayed first so
// workers are only ever paid for coverage beyond what the customer had.
func (c *Coordinator) CreateCampaign(ctx context.Context, spec CampaignSpec) (string, error) {
	if spec.Name == "" || spec.Customer == "" || spec.Executor == nil ||
		spec.Budget <= 0 || spec.PricePerEdge <= 0 || spec.PricePerCrash <= 0 {
		return "", ErrInvalidSpec
	}
	fee, err := spec.Budget.MulDiv(c.cfg.PlatformFeeBps, 10_000)
	if err != nil {
		return "", err
	}
	camp := &campaign{
		id: randomID("c"), name: spec.Name, customer: spec.Customer, exec: spec.Executor, builds: maps.Clone(spec.Builds),
		pricePerEdge: spec.PricePerEdge, pricePerCrash: spec.PricePerCrash,
		cov: coverage.NewMap(), corpusSeen: make(map[[32]byte]bool),
		crashes: make(map[string]*CrashRecord), open: true,
	}
	for _, seed := range spec.Seeds {
		ectx, cancel := context.WithTimeout(ctx, c.cfg.ExecTimeout)
		res, err := spec.Executor.Execute(ectx, seed)
		cancel()
		if err != nil {
			return "", fmt.Errorf("coordinator: replay seed: %w", err)
		}
		if res.Crash != nil {
			continue // a seed that already crashes is the customer's known bug
		}
		camp.cov.Add(res.Edges)
		camp.addCorpus(seed)
	}
	camp.baseline = camp.cov.Len()

	escrow := EscrowAccount(camp.id)
	if err := c.led.Transfer(spec.Customer, escrow, spec.Budget, "fund campaign "+camp.id); err != nil {
		return "", err
	}
	if fee > 0 {
		if err := c.led.Transfer(escrow, ledger.Platform, fee, "platform fee for "+camp.id); err != nil {
			return "", err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.campaigns[camp.id] = camp
	c.order = append(c.order, camp.id)
	return camp.id, nil
}

func (c *Coordinator) authLocked(id identity.WorkerID, nonce uint64, domain string, payload, sig []byte) (*workerState, error) {
	w := c.workers[id]
	if w == nil {
		return nil, ErrUnknownWorker
	}
	if !identity.Verify(w.pub, domain, payload, sig) {
		return nil, ErrBadSignature
	}
	if nonce <= w.lastNonce {
		return nil, ErrStaleNonce
	}
	w.lastNonce = nonce
	return w, nil
}

// Lease assigns the next open campaign that still has escrow, round-robin.
func (c *Coordinator) Lease(req protocol.LeaseRequest) (protocol.Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, err := c.authLocked(req.WorkerID, req.Nonce, protocol.DomainLease, req.SigningBytes(), req.Sig)
	if err != nil {
		return protocol.Lease{}, err
	}
	if c.led.Balance(StakeAccount(w.id)) < c.cfg.MinStake {
		return protocol.Lease{}, ErrNoStake
	}
	now := c.now()
	live := 0
	for id, l := range c.leases {
		if now.After(l.lease.ExpiresAt.Add(c.cfg.LeaseGrace)) {
			delete(c.leases, id)
		} else if l.worker == w.id {
			live++
		}
	}
	if live >= c.cfg.MaxLeasesPerWorker {
		return protocol.Lease{}, ErrLeaseExhausted
	}
	var camp *campaign
	for i := 0; i < len(c.order); i++ {
		cand := c.campaigns[c.order[(c.cursor+i)%len(c.order)]]
		if cand.open && c.led.Balance(EscrowAccount(cand.id)) > 0 {
			camp = cand
			c.cursor = (c.cursor + i + 1) % len(c.order)
			break
		}
	}
	if camp == nil {
		return protocol.Lease{}, ErrNoWork
	}
	l := protocol.Lease{
		ID: randomID("l"), CampaignID: camp.id, TargetDigest: camp.exec.Digest(), Builds: maps.Clone(camp.builds),
		ExpiresAt: now.Add(c.cfg.LeaseTTL), PricePerEdge: camp.pricePerEdge,
		PricePerCrash: camp.pricePerCrash, MaxInputs: c.cfg.MaxInputsPerSubmission,
		Seeds: camp.newestSeeds(c.cfg.SeedsPerLease),
	}
	c.leases[l.ID] = &leaseState{lease: l, worker: w.id}
	return l, nil
}

type replayed struct {
	res   target.Result
	err   error
	flaky bool
}

// Submit verifies a signed batch of inputs and pays for what checks out.
func (c *Coordinator) Submit(ctx context.Context, sub protocol.Submission) (protocol.SubmitResponse, error) {
	if len(sub.Inputs) == 0 || len(sub.Inputs) > c.cfg.MaxInputsPerSubmission {
		return protocol.SubmitResponse{}, ErrLimits
	}
	for _, in := range sub.Inputs {
		if len(in.Data) > c.cfg.MaxInputBytes {
			return protocol.SubmitResponse{}, ErrLimits
		}
	}

	c.mu.Lock()
	w, err := c.authLocked(sub.WorkerID, sub.Nonce, protocol.DomainSubmit, sub.SigningBytes(), sub.Sig)
	if err != nil {
		c.mu.Unlock()
		return protocol.SubmitResponse{}, err
	}
	ls := c.leases[sub.LeaseID]
	switch {
	case ls == nil:
		err = ErrUnknownLease
	case ls.worker != w.id:
		err = ErrLeaseOwner
	case c.now().After(ls.lease.ExpiresAt.Add(c.cfg.LeaseGrace)):
		err = ErrLeaseExpired
	case ls.submissions >= c.cfg.MaxSubmissionsPerLease:
		err = ErrLeaseExhausted
	}
	if err != nil {
		c.mu.Unlock()
		return protocol.SubmitResponse{}, err
	}
	camp := c.campaigns[ls.lease.CampaignID]
	if !camp.open {
		c.mu.Unlock()
		return protocol.SubmitResponse{}, ErrCampaignClosed
	}
	ls.submissions++
	c.mu.Unlock()

	// The expensive part runs outside the lock, and it is the whole point:
	// every input is executed again here, on the pinned target build.
	results := make([]replayed, len(sub.Inputs))
	for i, in := range sub.Inputs {
		results[i] = c.replay(ctx, camp.exec, in.Data)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	resp := protocol.SubmitResponse{Verdicts: make([]protocol.Verdict, 0, len(sub.Inputs))}
	for i, in := range sub.Inputs {
		r := results[i]
		var v protocol.Verdict
		switch {
		case r.err != nil:
			v.Status = protocol.StatusVerifierError // our problem, not the worker's
		case r.flaky:
			v.Status = protocol.StatusFlakyCrash
		case r.res.Crash != nil:
			v = c.creditCrashLocked(camp, w, in.Data, r.res.Crash)
		case in.ClaimCrash:
			v.Status = protocol.StatusFalseCrash
			v.Slashed = c.slashLocked(camp, w)
		default:
			v = c.creditCoverageLocked(camp, w, in.Data, r.res.Edges)
		}
		v.Index = i
		w.verdicts[v.Status]++
		resp.Verdicts = append(resp.Verdicts, v)
		resp.Paid += v.Paid
		resp.Slashed += v.Slashed
	}
	resp.EscrowRemaining = c.led.Balance(EscrowAccount(camp.id))
	if resp.EscrowRemaining == 0 {
		camp.open = false
	}
	resp.CampaignOpen = camp.open
	return resp, nil
}

func (c *Coordinator) replay(ctx context.Context, exec target.Executor, input []byte) replayed {
	run := func() (target.Result, error) {
		ectx, cancel := context.WithTimeout(ctx, c.cfg.ExecTimeout)
		defer cancel()
		return exec.Execute(ectx, input)
	}
	res, err := run()
	if err != nil || res.Crash == nil {
		return replayed{res: res, err: err}
	}
	// A crash counts only if it reproduces with the same signature.
	again, err := run()
	if err != nil {
		return replayed{err: err}
	}
	if again.Crash == nil || again.Crash.Signature != res.Crash.Signature {
		return replayed{res: res, flaky: true}
	}
	return replayed{res: res}
}

func (c *Coordinator) creditCoverageLocked(camp *campaign, w *workerState, input []byte, edges []coverage.Edge) protocol.Verdict {
	novel := camp.cov.Novel(edges)
	if len(novel) == 0 {
		return protocol.Verdict{Status: protocol.StatusNoNewCoverage}
	}
	due, err := camp.pricePerEdge.MulInt(int64(len(novel)))
	if err != nil {
		due = money.Amount(math.MaxInt64)
	}
	paid := c.payLocked(camp, w, due, fmt.Sprintf("%d new edges in %s", len(novel), camp.id))
	camp.cov.Add(novel)
	camp.addCorpus(input)
	return protocol.Verdict{Status: protocol.StatusNewCoverage, NewEdges: len(novel), Paid: paid}
}

func (c *Coordinator) creditCrashLocked(camp *campaign, w *workerState, input []byte, cr *target.Crash) protocol.Verdict {
	v := protocol.Verdict{CrashKind: cr.Kind, CrashSignature: cr.Signature}
	if _, known := camp.crashes[cr.Signature]; known {
		v.Status = protocol.StatusKnownCrash
		return v
	}
	v.Status = protocol.StatusNewCrash
	v.Paid = c.payLocked(camp, w, camp.pricePerCrash, "crash "+cr.Signature+" in "+camp.id)
	camp.crashes[cr.Signature] = &CrashRecord{
		Signature: cr.Signature, Kind: cr.Kind, Frames: cr.Frames,
		FoundBy: w.id, FoundAt: c.now(), Paid: v.Paid, input: append([]byte(nil), input...),
	}
	camp.crashOrder = append(camp.crashOrder, cr.Signature)
	return v
}

func (c *Coordinator) payLocked(camp *campaign, w *workerState, due money.Amount, memo string) money.Amount {
	paid, err := c.led.TransferUpTo(EscrowAccount(camp.id), WalletAccount(w.id), due, memo)
	if err != nil {
		return 0
	}
	camp.paid += paid
	w.earned += paid
	return paid
}

// slashLocked moves the false-claim penalty from the worker's stake into the
// campaign escrow, compensating the customer for wasted verification.
func (c *Coordinator) slashLocked(camp *campaign, w *workerState) money.Amount {
	moved, err := c.led.TransferUpTo(StakeAccount(w.id), EscrowAccount(camp.id), c.cfg.FalseCrashPenalty, "slash: crash claim did not reproduce")
	if err != nil {
		return 0
	}
	w.slashed += moved
	return moved
}

func (camp *campaign) addCorpus(input []byte) {
	h := sha256.Sum256(input)
	if camp.corpusSeen[h] {
		return
	}
	camp.corpusSeen[h] = true
	camp.corpus = append(camp.corpus, append([]byte(nil), input...))
}

func (camp *campaign) newestSeeds(n int) [][]byte {
	start := max(0, len(camp.corpus)-n)
	out := make([][]byte, 0, len(camp.corpus)-start)
	for _, s := range camp.corpus[start:] {
		out = append(out, append([]byte(nil), s...))
	}
	return out
}

func (c *Coordinator) Campaign(id string) (CampaignStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	camp := c.campaigns[id]
	if camp == nil {
		return CampaignStats{}, ErrUnknownCampaign
	}
	st := CampaignStats{
		ID: camp.id, Name: camp.name, TargetDigest: camp.exec.Digest(), Open: camp.open,
		EscrowRemaining: c.led.Balance(EscrowAccount(camp.id)), PaidOut: camp.paid,
		BaselineEdges: camp.baseline, Edges: camp.cov.Len(), CorpusSize: len(camp.corpus),
	}
	for _, sig := range camp.crashOrder {
		st.Crashes = append(st.Crashes, *camp.crashes[sig])
	}
	return st, nil
}

func (c *Coordinator) CampaignIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.order...)
}

// Reproducer returns the crashing input for the customer.
func (c *Coordinator) Reproducer(campaignID, signature string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	camp := c.campaigns[campaignID]
	if camp == nil {
		return nil, ErrUnknownCampaign
	}
	cr := camp.crashes[signature]
	if cr == nil {
		return nil, ErrUnknownCampaign
	}
	return append([]byte(nil), cr.input...), nil
}

func (c *Coordinator) Worker(id identity.WorkerID) (WorkerStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.workers[id]
	if w == nil {
		return WorkerStats{}, ErrUnknownWorker
	}
	verdicts := make(map[string]int, len(w.verdicts))
	for k, v := range w.verdicts {
		verdicts[k] = v
	}
	return WorkerStats{
		ID: id, Wallet: c.led.Balance(WalletAccount(id)), Stake: c.led.Balance(StakeAccount(id)),
		Earned: w.earned, Slashed: w.slashed, Verdicts: verdicts,
	}, nil
}

// WorkerIDs lists registered workers in a stable order.
func (c *Coordinator) WorkerIDs() []identity.WorkerID {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]identity.WorkerID, 0, len(c.workers))
	for id := range c.workers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func randomID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
