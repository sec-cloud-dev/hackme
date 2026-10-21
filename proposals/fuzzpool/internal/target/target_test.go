package target

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"fuzzpool/internal/coverage"
)

func run(t *testing.T, in string) Result {
	t.Helper()
	res, err := TinyParse{}.Execute(context.Background(), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTinyParseCoverage(t *testing.T) {
	got := run(t, "FZ\x01\x00").Edges
	want := []coverage.Edge{1, 4, 6, 7, 11}
	if !slices.Equal(got, want) {
		t.Fatalf("edges %v, want %v", got, want)
	}
	if run(t, "AAAA").Crash != nil {
		t.Fatal("benign input crashed")
	}
}

func TestTinyParseCrashSignatures(t *testing.T) {
	a1 := run(t, "FZ\x02\x05ab").Crash
	a2 := run(t, "FZ\x02\x09xyz").Crash // same bug, different values
	b := run(t, "FZ\x80\x02\xde\xad").Crash
	if a1 == nil || a2 == nil || b == nil {
		t.Fatalf("planted bugs not hit: %v %v %v", a1, a2, b)
	}
	if a1.Signature != a2.Signature {
		t.Errorf("same bug, different signatures: %+v vs %+v", a1, a2)
	}
	if a1.Signature == b.Signature {
		t.Errorf("different bugs share a signature: %+v", a1)
	}
	if a1.Kind != "go:index-out-of-range" || b.Kind != "go:nil-map-write" {
		t.Errorf("kinds %q, %q", a1.Kind, b.Kind)
	}
	if len(a1.Frames) == 0 || !slices.ContainsFunc(a1.Frames, func(f string) bool { return strings.HasPrefix(f, "target.tinyParse:") }) {
		t.Errorf("frames do not point at the bug: %v", a1.Frames)
	}
}

const asanReport = `==31337==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x5130a4 bp 0x7ffc sp 0x7ffc
READ of size 1 at 0x602000000011 thread T0
    #0 0x4a1b20 in __interceptor_memcpy /llvm/compiler-rt/asan_interceptors.cpp:22:3
    #1 0x5130a3 in parse_record /src/tiny/parse.c:42:13
    #2 0x513421 in LLVMFuzzerTestOneInput /src/tiny/fuzz.c:9:3
    #3 0x43b5c1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm/FuzzerLoop.cpp:611:15
    #4 0x7f00 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/tiny/parse.c:42:13 in parse_record`

func TestParseSanitizerReport(t *testing.T) {
	c := ParseSanitizerReport([]byte(asanReport))
	if c == nil {
		t.Fatal("ASan report not recognised")
	}
	if c.Kind != "asan:heap-buffer-overflow" {
		t.Errorf("kind %q", c.Kind)
	}
	want := []string{"parse_record parse.c:42", "LLVMFuzzerTestOneInput fuzz.c:9"}
	if !slices.Equal(c.Frames, want) {
		t.Errorf("frames %q, want %q", c.Frames, want)
	}
	// Same bug built in another directory must keep its identity.
	moved := ParseSanitizerReport([]byte(`==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1 in parse_record /home/ci/build/parse.c:42:9
    #1 0x2 in LLVMFuzzerTestOneInput /home/ci/build/fuzz.c:9:1`))
	if moved.Signature != c.Signature {
		t.Error("signature depends on build path")
	}
	for _, benign := range []string{"", "INFO: Running with entropic power schedule\nDone 1 runs in 0 second(s)\n"} {
		if ParseSanitizerReport([]byte(benign)) != nil {
			t.Errorf("crash invented from %q", benign)
		}
	}
	if c := ParseSanitizerReport([]byte("x.c:3:5: runtime error: signed integer overflow\n")); c == nil || c.Kind != "ubsan:runtime-error" {
		t.Errorf("UBSan not recognised: %+v", c)
	}
}

func TestParseShowmap(t *testing.T) {
	edges, err := ParseShowmap([]byte("000123:1\n000007:3\n000123:2\n"))
	if err != nil || !slices.Equal(edges, []coverage.Edge{7, 123}) {
		t.Fatalf("%v %v", edges, err)
	}
	if _, err := ParseShowmap([]byte("garbage\n")); err == nil {
		t.Fatal("malformed map accepted")
	}
}

// A fake libFuzzer-style binary: crashes with an ASan report on "BOOM".
func TestBinaryExecutor(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "target.sh")
	script := `#!/bin/sh
if grep -q BOOM "$1"; then
  echo "==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1" >&2
  echo "    #0 0x1 in handle_boom /src/t.c:5:2" >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBinary(bin, "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Digest()) != len("sha256:")+64 {
		t.Fatalf("digest %q", b.Digest())
	}
	res, err := b.Execute(context.Background(), []byte("hello"))
	if err != nil || res.Crash != nil {
		t.Fatalf("benign: %+v %v", res, err)
	}
	res, err = b.Execute(context.Background(), []byte("xxBOOMxx"))
	if err != nil || res.Crash == nil || res.Crash.Kind != "asan:stack-buffer-overflow" {
		t.Fatalf("crash: %+v %v", res, err)
	}
}
