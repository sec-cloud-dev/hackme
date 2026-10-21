// Package protocol defines the coordinator <-> worker wire format.
//
// Note what is absent: there is no hashrate, attempt count, exec/s, duration
// or "edges touched" field. A worker sends inputs; the coordinator measures
// them itself. Unknown JSON fields are rejected, so such claims cannot even
// be smuggled in.
package protocol

import (
	"encoding/json"
	"time"

	"fuzzpool/internal/identity"
	"fuzzpool/internal/money"
)

// Signature domains: a signature for one message type is useless for another.
const (
	DomainRegister = "fuzzpool/register/v1"
	DomainLease    = "fuzzpool/lease/v1"
	DomainSubmit   = "fuzzpool/submit/v1"
)

type RegisterRequest struct {
	PublicKey []byte `json:"public_key"`
	Sig       []byte `json:"sig"` // proof of possession: signs PublicKey
}

type RegisterResponse struct {
	WorkerID identity.WorkerID `json:"worker_id"`
}

type LeaseRequest struct {
	WorkerID identity.WorkerID `json:"worker_id"`
	Nonce    uint64            `json:"nonce"` // strictly increasing per worker
	Sig      []byte            `json:"sig,omitempty"`
}

func (r LeaseRequest) SigningBytes() []byte { r.Sig = nil; return mustJSON(r) }

// Lease hands a worker a campaign to fuzz. Seeds are the campaign's current
// verified corpus, so every worker builds on everyone's progress.
//
// TargetDigest pins the build the coordinator verifies with (AFL++
// instrumented, so afl-showmap can measure it; afl-fuzz runs it directly).
// Builds pins other engine builds of the same source, e.g. "libfuzzer".
type Lease struct {
	ID            string            `json:"id"`
	CampaignID    string            `json:"campaign_id"`
	TargetDigest  string            `json:"target_digest"`
	Builds        map[string]string `json:"builds,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	PricePerEdge  money.Amount      `json:"price_per_edge"`
	PricePerCrash money.Amount      `json:"price_per_crash"`
	MaxInputs     int               `json:"max_inputs"`
	Seeds         [][]byte          `json:"seeds"`
}

// Input is a candidate the worker believes is interesting. ClaimCrash marks
// inputs the worker says crash the target; a false claim costs stake,
// because crash verification is the expensive check.
type Input struct {
	Data       []byte `json:"data"`
	ClaimCrash bool   `json:"claim_crash,omitempty"`
}

type Submission struct {
	WorkerID identity.WorkerID `json:"worker_id"`
	LeaseID  string            `json:"lease_id"`
	Nonce    uint64            `json:"nonce"`
	Inputs   []Input           `json:"inputs"`
	Sig      []byte            `json:"sig,omitempty"`
}

func (s Submission) SigningBytes() []byte { s.Sig = nil; return mustJSON(s) }

const (
	StatusNewCoverage   = "new_coverage"
	StatusNoNewCoverage = "no_new_coverage"
	StatusNewCrash      = "new_crash"
	StatusKnownCrash    = "known_crash"
	StatusFlakyCrash    = "flaky_crash"
	StatusFalseCrash    = "false_crash_claim"
	StatusVerifierError = "verifier_error"
)

// Verdict is the coordinator's own measurement of one input.
type Verdict struct {
	Index          int          `json:"index"`
	Status         string       `json:"status"`
	NewEdges       int          `json:"new_edges,omitempty"`
	CrashKind      string       `json:"crash_kind,omitempty"`
	CrashSignature string       `json:"crash_signature,omitempty"`
	Paid           money.Amount `json:"paid"`
	Slashed        money.Amount `json:"slashed"`
}

type SubmitResponse struct {
	Verdicts        []Verdict    `json:"verdicts"`
	Paid            money.Amount `json:"paid"`
	Slashed         money.Amount `json:"slashed"`
	EscrowRemaining money.Amount `json:"escrow_remaining"`
	CampaignOpen    bool         `json:"campaign_open"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
