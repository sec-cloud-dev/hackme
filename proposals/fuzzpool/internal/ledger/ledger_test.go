package ledger

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"fuzzpool/internal/money"
)

func TestTransferRules(t *testing.T) {
	l := New()
	if err := l.Deposit("customer:a", money.MustParse("10"), "card"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transfer("customer:a", "escrow:x", money.MustParse("10.000001"), ""); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("overdraft allowed: %v", err)
	}
	if err := l.Transfer("customer:a", "escrow:x", 0, ""); !errors.Is(err, ErrBadAmount) {
		t.Fatalf("zero transfer allowed: %v", err)
	}
	if err := l.Transfer("customer:a", "customer:a", 1, ""); !errors.Is(err, ErrBadAccount) {
		t.Fatalf("self transfer allowed: %v", err)
	}
	moved, err := l.TransferUpTo("customer:a", "escrow:x", money.MustParse("25"), "")
	if err != nil || moved != money.MustParse("10") {
		t.Fatalf("TransferUpTo moved %s, %v", moved, err)
	}
	if moved, _ := l.TransferUpTo("customer:a", "escrow:x", 1, ""); moved != 0 {
		t.Fatalf("empty account paid %s", moved)
	}
	if err := l.CheckInvariant(); err != nil {
		t.Fatal(err)
	}
}

// Random operations must never break conservation of money.
func TestInvariantUnderRandomOps(t *testing.T) {
	l := New()
	r := rand.New(rand.NewPCG(7, 7))
	accts := []Account{External, Platform, "a", "b", "c", "d"}
	for i := 0; i < 20_000; i++ {
		from, to := accts[r.IntN(len(accts))], accts[r.IntN(len(accts))]
		amt := money.Amount(r.Int64N(5_000_000) - 1_000)
		if r.IntN(2) == 0 {
			_ = l.Transfer(from, to, amt, fmt.Sprint(i))
		} else {
			_, _ = l.TransferUpTo(from, to, amt, fmt.Sprint(i))
		}
	}
	if err := l.CheckInvariant(); err != nil {
		t.Fatal(err)
	}
	if len(l.Journal()) == 0 {
		t.Fatal("no operations applied")
	}
}

func TestInvariantDetectsTampering(t *testing.T) {
	l := New()
	_ = l.Deposit("a", money.MustParse("1"), "")
	l.balance["a"] += 1 // a bug or an attacker editing the table directly
	if err := l.CheckInvariant(); err == nil {
		t.Fatal("tampered balance not detected")
	}
}
