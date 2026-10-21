// Package identity binds a worker to an Ed25519 key. A worker ID is the full
// SHA-256 of the public key (256 bits), never a truncated prefix, and every
// signature carries a domain tag so it cannot be replayed for another purpose.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type WorkerID string

func IDFromPublicKey(pub ed25519.PublicKey) WorkerID {
	sum := sha256.Sum256(pub)
	return WorkerID(hex.EncodeToString(sum[:]))
}

func (id WorkerID) Valid() bool {
	b, err := hex.DecodeString(string(id))
	return err == nil && len(b) == sha256.Size
}

func message(domain string, payload []byte) []byte {
	m := make([]byte, 0, len(domain)+1+len(payload))
	m = append(m, domain...)
	m = append(m, 0)
	return append(m, payload...)
}

type Signer struct {
	priv ed25519.PrivateKey
}

func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv}, nil
}

func SignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity: seed must be 32 bytes")
	}
	return &Signer{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func (s *Signer) Seed() []byte                 { return s.priv.Seed() }
func (s *Signer) PublicKey() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s *Signer) ID() WorkerID                 { return IDFromPublicKey(s.PublicKey()) }

func (s *Signer) Sign(domain string, payload []byte) []byte {
	return ed25519.Sign(s.priv, message(domain, payload))
}

func Verify(pub ed25519.PublicKey, domain string, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message(domain, payload), sig)
}
