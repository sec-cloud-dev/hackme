package coordinator

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"fuzzpool/internal/identity"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/money"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
)

// Server exposes the coordinator over HTTP. Worker endpoints are
// authenticated by Ed25519 signatures with per-worker nonces; customer and
// payment-gateway endpoints by an admin bearer token (a real deployment
// would use per-customer keys and gateway webhooks instead).
type Server struct {
	Coord      *Coordinator
	Ledger     *ledger.Ledger
	AdminToken string
	Targets    map[string]target.Executor
	Builds     map[string]map[string]string // target name -> engine -> worker build digest
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/workers", s.register)
	mux.HandleFunc("GET /v1/workers/{id}", s.worker)
	mux.HandleFunc("POST /v1/leases", s.lease)
	mux.HandleFunc("POST /v1/submissions", s.submit)
	mux.HandleFunc("GET /v1/campaigns", s.campaigns)
	mux.HandleFunc("GET /v1/campaigns/{id}", s.campaign)
	mux.HandleFunc("GET /v1/ledger/invariant", s.invariant)
	mux.HandleFunc("POST /v1/admin/deposits", s.admin(s.deposit))
	mux.HandleFunc("POST /v1/admin/campaigns", s.admin(s.createCampaign))
	mux.HandleFunc("GET /v1/admin/balances", s.admin(s.balances))
	mux.HandleFunc("GET /v1/admin/campaigns/{id}/crashes/{sig}", s.admin(s.reproducer))
	return mux
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if !decode(w, r, &req, 4<<10) {
		return
	}
	id, err := s.Coord.Register(req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{WorkerID: id})
}

func (s *Server) worker(w http.ResponseWriter, r *http.Request) {
	st, err := s.Coord.Worker(identity.WorkerID(r.PathValue("id")))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) lease(w http.ResponseWriter, r *http.Request) {
	var req protocol.LeaseRequest
	if !decode(w, r, &req, 4<<10) {
		return
	}
	l, err := s.Coord.Lease(req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	cfg := s.Coord.Config()
	// base64 inflates by 4/3; leave headroom for JSON framing.
	limit := int64(cfg.MaxInputsPerSubmission)*int64(cfg.MaxInputBytes)*4/3 + 64<<10
	var sub protocol.Submission
	if !decode(w, r, &sub, limit) {
		return
	}
	resp, err := s.Coord.Submit(r.Context(), sub)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) campaigns(w http.ResponseWriter, r *http.Request) {
	out := []CampaignStats{}
	for _, id := range s.Coord.CampaignIDs() {
		if st, err := s.Coord.Campaign(id); err == nil {
			out = append(out, st)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) campaign(w http.ResponseWriter, r *http.Request) {
	st, err := s.Coord.Campaign(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) invariant(w http.ResponseWriter, r *http.Request) {
	if err := s.Ledger.CheckInvariant(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": len(s.Ledger.Journal())})
}

type depositRequest struct {
	Account ledger.Account `json:"account"`
	Amount  money.Amount   `json:"amount"`
	Memo    string         `json:"memo"`
}

func (s *Server) deposit(w http.ResponseWriter, r *http.Request) {
	var req depositRequest
	if !decode(w, r, &req, 4<<10) {
		return
	}
	if err := s.Ledger.Deposit(req.Account, req.Amount, req.Memo); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": req.Account, "balance": s.Ledger.Balance(req.Account)})
}

type createCampaignRequest struct {
	Name          string         `json:"name"`
	Customer      ledger.Account `json:"customer"`
	Budget        money.Amount   `json:"budget"`
	PricePerEdge  money.Amount   `json:"price_per_edge"`
	PricePerCrash money.Amount   `json:"price_per_crash"`
	Target        string         `json:"target"`
	Seeds         [][]byte       `json:"seeds"`
}

func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request) {
	var req createCampaignRequest
	if !decode(w, r, &req, 16<<20) {
		return
	}
	exec := s.Targets[req.Target]
	if exec == nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "unknown target " + req.Target})
		return
	}
	id, err := s.Coord.CreateCampaign(r.Context(), CampaignSpec{
		Name: req.Name, Customer: req.Customer, Budget: req.Budget,
		PricePerEdge: req.PricePerEdge, PricePerCrash: req.PricePerCrash,
		Executor: exec, Builds: s.Builds[req.Target], Seeds: req.Seeds,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	st, _ := s.Coord.Campaign(id)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) balances(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ledger.Balances())
}

func (s *Server) reproducer(w http.ResponseWriter, r *http.Request) {
	data, err := s.Coord.Reproducer(r.PathValue("id"), r.PathValue("sig"))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + s.AdminToken
		got := r.Header.Get("Authorization")
		if s.AdminToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: "admin token required"})
			return
		}
		h(w, r)
	}
}

// decode rejects unknown fields: a worker cannot even send "hashrate".
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, protocol.ErrorResponse{Error: err.Error()})
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, ErrBadSignature), errors.Is(err, ErrUnknownWorker):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrStaleNonce):
		status = http.StatusConflict
	case errors.Is(err, ErrNoStake), errors.Is(err, ledger.ErrInsufficient):
		status = http.StatusPaymentRequired
	case errors.Is(err, ErrLeaseOwner):
		status = http.StatusForbidden
	case errors.Is(err, ErrUnknownLease), errors.Is(err, ErrUnknownCampaign), errors.Is(err, ErrNoWork):
		status = http.StatusNotFound
	case errors.Is(err, ErrLeaseExpired), errors.Is(err, ErrCampaignClosed):
		status = http.StatusGone
	case errors.Is(err, ErrLeaseExhausted):
		status = http.StatusTooManyRequests
	case errors.Is(err, ErrLimits):
		status = http.StatusRequestEntityTooLarge
	}
	writeJSON(w, status, protocol.ErrorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
