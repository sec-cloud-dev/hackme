// Package ledger is a double-entry, append-only journal of integer amounts.
//
// Money enters only from the External account (a customer payment or a
// worker stake confirmed by a payment gateway) and leaves only back to it.
// Nothing is ever minted: the sum of all balances, External included, is
// always zero, and CheckInvariant proves it by replaying the whole journal.
package ledger

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"fuzzpool/internal/money"
)

// Account names a balance, e.g. "customer:acme", "escrow:c-…", "worker:…".
type Account string

const (
	// External is the outside world. It is the only account allowed to go
	// negative: its balance is minus everything that was paid in.
	External Account = "external"
	// Platform collects the fee that is disclosed when a campaign is created.
	Platform Account = "platform"
)

var (
	ErrInsufficient = errors.New("ledger: insufficient funds")
	ErrBadAmount    = errors.New("ledger: amount must be positive")
	ErrBadAccount   = errors.New("ledger: invalid account")
)

// Entry is one immutable journal line.
type Entry struct {
	Seq    uint64       `json:"seq"`
	At     time.Time    `json:"at"`
	From   Account      `json:"from"`
	To     Account      `json:"to"`
	Amount money.Amount `json:"amount"`
	Memo   string       `json:"memo"`
}

type Ledger struct {
	now func() time.Time

	mu      sync.Mutex
	balance map[Account]money.Amount
	journal []Entry
}

func New() *Ledger {
	return &Ledger{now: time.Now, balance: make(map[Account]money.Amount)}
}

// Deposit records money arriving from outside (after the payment cleared).
func (l *Ledger) Deposit(to Account, amt money.Amount, memo string) error {
	return l.Transfer(External, to, amt, memo)
}

// Withdraw records money leaving to the outside world.
func (l *Ledger) Withdraw(from Account, amt money.Amount, memo string) error {
	return l.Transfer(from, External, amt, memo)
}

func (l *Ledger) Transfer(from, to Account, amt money.Amount, memo string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.transferLocked(from, to, amt, memo)
}

// TransferUpTo moves min(max, balance(from)) and reports how much moved.
// Escrow payouts use it so a campaign can never pay out more than it holds.
func (l *Ledger) TransferUpTo(from, to Account, max money.Amount, memo string) (money.Amount, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	amt := max
	if from != External && l.balance[from] < amt {
		amt = l.balance[from]
	}
	if amt <= 0 {
		return 0, nil
	}
	if err := l.transferLocked(from, to, amt, memo); err != nil {
		return 0, err
	}
	return amt, nil
}

func (l *Ledger) transferLocked(from, to Account, amt money.Amount, memo string) error {
	if amt <= 0 {
		return ErrBadAmount
	}
	if from == "" || to == "" || from == to {
		return ErrBadAccount
	}
	fb := l.balance[from]
	if from != External && fb < amt {
		return fmt.Errorf("%w: %s has %s, needs %s", ErrInsufficient, from, fb, amt)
	}
	if from == External && fb < money.Amount(math.MinInt64)+amt {
		return money.ErrOverflow
	}
	tb := l.balance[to]
	if tb > money.Amount(math.MaxInt64)-amt {
		return money.ErrOverflow
	}
	l.balance[from] = fb - amt
	l.balance[to] = tb + amt
	l.journal = append(l.journal, Entry{
		Seq: uint64(len(l.journal)) + 1, At: l.now(), From: from, To: to, Amount: amt, Memo: memo,
	})
	return nil
}

func (l *Ledger) Balance(a Account) money.Amount {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balance[a]
}

// Balances returns a snapshot of every non-zero balance, sorted by account.
func (l *Ledger) Balances() []AccountBalance {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AccountBalance, 0, len(l.balance))
	for a, b := range l.balance {
		if b != 0 {
			out = append(out, AccountBalance{Account: a, Balance: b})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account < out[j].Account })
	return out
}

type AccountBalance struct {
	Account Account      `json:"account"`
	Balance money.Amount `json:"balance"`
}

// Journal returns a copy of every entry.
func (l *Ledger) Journal() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.journal...)
}

// CheckInvariant replays the journal from scratch and verifies that it
// reproduces every balance, that no internal account is negative, and that
// all balances sum to exactly zero (nothing was created out of thin air).
func (l *Ledger) CheckInvariant() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	replay := make(map[Account]*big.Int)
	get := func(a Account) *big.Int {
		if replay[a] == nil {
			replay[a] = new(big.Int)
		}
		return replay[a]
	}
	for _, e := range l.journal {
		get(e.From).Sub(get(e.From), big.NewInt(int64(e.Amount)))
		get(e.To).Add(get(e.To), big.NewInt(int64(e.Amount)))
	}
	sum := new(big.Int)
	for a, b := range l.balance {
		if get(a).Cmp(big.NewInt(int64(b))) != 0 {
			return fmt.Errorf("ledger: %s balance %s does not match journal %s", a, b, get(a))
		}
		if a != External && b < 0 {
			return fmt.Errorf("ledger: %s is negative: %s", a, b)
		}
		sum.Add(sum, big.NewInt(int64(b)))
	}
	for a, v := range replay {
		if _, ok := l.balance[a]; !ok && v.Sign() != 0 {
			return fmt.Errorf("ledger: journal has balance for unknown account %s", a)
		}
	}
	if sum.Sign() != 0 {
		return fmt.Errorf("ledger: balances sum to %s micro-units, want 0", sum)
	}
	return nil
}
