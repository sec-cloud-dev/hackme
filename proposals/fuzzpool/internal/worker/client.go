// Package worker is the fuzzing side: it leases campaigns, runs an engine
// (libFuzzer, AFL++ or the built-in demo mutator) and submits what the engine
// kept. It never reports metrics about itself; it only proposes inputs.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"fuzzpool/internal/identity"
	"fuzzpool/internal/protocol"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Signer  *identity.Signer

	mu        sync.Mutex
	lastNonce uint64
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("coordinator: HTTP %d: %s", e.Status, e.Message)
}

// nextNonce is time-based so a restarted worker never reuses a nonce.
func (c *Client) nextNonce() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := uint64(time.Now().UnixNano())
	if n <= c.lastNonce {
		n = c.lastNonce + 1
	}
	c.lastNonce = n
	return n
}

func (c *Client) Register(ctx context.Context) (identity.WorkerID, error) {
	pub := c.Signer.PublicKey()
	var resp protocol.RegisterResponse
	err := c.Do(ctx, http.MethodPost, "/v1/workers",
		protocol.RegisterRequest{PublicKey: pub, Sig: c.Signer.Sign(protocol.DomainRegister, pub)}, &resp)
	return resp.WorkerID, err
}

func (c *Client) Lease(ctx context.Context) (protocol.Lease, error) {
	req := protocol.LeaseRequest{WorkerID: c.Signer.ID(), Nonce: c.nextNonce()}
	req.Sig = c.Signer.Sign(protocol.DomainLease, req.SigningBytes())
	var l protocol.Lease
	err := c.Do(ctx, http.MethodPost, "/v1/leases", req, &l)
	return l, err
}

// NewSubmission builds and signs a submission without sending it.
func (c *Client) NewSubmission(leaseID string, inputs []protocol.Input) protocol.Submission {
	sub := protocol.Submission{WorkerID: c.Signer.ID(), LeaseID: leaseID, Nonce: c.nextNonce(), Inputs: inputs}
	sub.Sig = c.Signer.Sign(protocol.DomainSubmit, sub.SigningBytes())
	return sub
}

func (c *Client) Send(ctx context.Context, sub protocol.Submission) (protocol.SubmitResponse, error) {
	var resp protocol.SubmitResponse
	err := c.Do(ctx, http.MethodPost, "/v1/submissions", sub, &resp)
	return resp, err
}

func (c *Client) Submit(ctx context.Context, leaseID string, inputs []protocol.Input) (protocol.SubmitResponse, error) {
	return c.Send(ctx, c.NewSubmission(leaseID, inputs))
}

// Do sends a JSON request; in may be a value or raw []byte.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	switch v := in.(type) {
	case nil:
	case []byte:
		body = bytes.NewReader(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e protocol.ErrorResponse
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
