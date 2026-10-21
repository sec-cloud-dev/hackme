package money

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParseFormat(t *testing.T) {
	cases := map[string]string{
		"0":                    "0.000000",
		"1":                    "1.000000",
		"0.5":                  "0.500000",
		".25":                  "0.250000",
		"-3.000001":            "-3.000001",
		"+7.1":                 "7.100000",
		"9223372036854.775807": "9223372036854.775807",
	}
	for in, want := range cases {
		a, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if a.String() != want {
			t.Errorf("Parse(%q) = %s, want %s", in, a, want)
		}
	}
	if Amount(math.MinInt64).String() != "-9223372036854.775808" {
		t.Errorf("MinInt64 formatted as %s", Amount(math.MinInt64))
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "-", ".", "1.", "1.0000001", "abc", "1e5", "9223372036854.775808", "1_000", "--1"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestMulDiv(t *testing.T) {
	fee, err := MustParse("100").MulDiv(500, 10_000)
	if err != nil || fee != MustParse("5") {
		t.Fatalf("5%% of 100 = %s, %v", fee, err)
	}
	if _, err := Amount(math.MaxInt64).MulInt(2); err != ErrOverflow {
		t.Fatalf("want overflow, got %v", err)
	}
}

func TestJSONIsString(t *testing.T) {
	b, _ := json.Marshal(struct{ A Amount }{MustParse("1.5")})
	if string(b) != `{"A":"1.500000"}` {
		t.Fatalf("got %s", b)
	}
	var v struct{ A Amount }
	if err := json.Unmarshal([]byte(`{"A":1.5}`), &v); err == nil {
		t.Fatal("JSON number accepted; floats must never reach balances")
	}
	if err := json.Unmarshal([]byte(`{"A":"2.25"}`), &v); err != nil || v.A != MustParse("2.25") {
		t.Fatalf("got %s, %v", v.A, err)
	}
}
