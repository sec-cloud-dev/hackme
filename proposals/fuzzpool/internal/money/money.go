// Package money implements fixed-point amounts. Every balance is an integer
// number of micro-units; floating point never touches accounting, and amounts
// travel over JSON as decimal strings ("12.500000"), never as JSON numbers.
package money

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Amount is a value in micro-units: 1.000000 == 1_000_000.
type Amount int64

const (
	Micro Amount = 1
	Unit  Amount = 1_000_000
)

const decimals = 6

var ErrOverflow = errors.New("money: overflow")

// String formats the amount with exactly six decimals.
func (a Amount) String() string {
	neg := a < 0
	u := uint64(a)
	if neg {
		u = -u // correct for MinInt64 as well
	}
	s := fmt.Sprintf("%d.%06d", u/uint64(Unit), u%uint64(Unit))
	if neg {
		return "-" + s
	}
	return s
}

// Parse reads a decimal string such as "12", "0.5" or "-3.000001".
// More than six decimals is an error rather than a silent rounding.
func Parse(s string) (Amount, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("money: empty amount")
	}
	neg := false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		s = s[1:]
	}
	whole, frac, hasDot := strings.Cut(s, ".")
	if whole == "" && frac == "" {
		return 0, fmt.Errorf("money: invalid amount %q", s)
	}
	if hasDot && frac == "" {
		return 0, fmt.Errorf("money: invalid amount %q", s)
	}
	if len(frac) > decimals {
		return 0, fmt.Errorf("money: %q has more than %d decimals", s, decimals)
	}
	if whole == "" {
		whole = "0"
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("money: invalid amount %q", s)
	}
	var f uint64
	if frac != "" {
		f, err = strconv.ParseUint(frac+strings.Repeat("0", decimals-len(frac)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("money: invalid amount %q", s)
		}
	}
	if w > (math.MaxInt64-f)/uint64(Unit) {
		return 0, ErrOverflow
	}
	v := int64(w*uint64(Unit) + f)
	if neg {
		v = -v
	}
	return Amount(v), nil
}

// MustParse is Parse for constants in code and tests.
func MustParse(s string) Amount {
	a, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return a
}

// MulDiv returns a*num/den rounded toward zero, failing on overflow.
func (a Amount) MulDiv(num, den int64) (Amount, error) {
	if den == 0 {
		return 0, errors.New("money: division by zero")
	}
	r := new(big.Int).Mul(big.NewInt(int64(a)), big.NewInt(num))
	r.Quo(r, big.NewInt(den))
	if !r.IsInt64() {
		return 0, ErrOverflow
	}
	return Amount(r.Int64()), nil
}

// MulInt returns a*n, failing on overflow.
func (a Amount) MulInt(n int64) (Amount, error) { return a.MulDiv(n, 1) }

func (a Amount) MarshalJSON() ([]byte, error) { return json.Marshal(a.String()) }

func (a *Amount) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("money: amount must be a decimal string, e.g. \"1.5\"")
	}
	v, err := Parse(s)
	if err != nil {
		return err
	}
	*a = v
	return nil
}
