package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func bwrapOrSkip(t *testing.T) Bwrap {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	b := Bwrap{}
	dir := t.TempDir()
	if err := b.Command(context.Background(), Spec{Workdir: dir, Argv: []string{"/bin/true"}}).Run(); err != nil {
		t.Skipf("bwrap cannot create namespaces here: %v", err)
	}
	return b
}

func TestBwrapIsolation(t *testing.T) {
	b := bwrapOrSkip(t)
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FUZZPOOL_LEAK_CHECK", "leaked")
	script := `
ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')
echo "ifaces=$ifaces"
cat ` + secret + ` >/dev/null 2>&1 && echo "secret=visible" || echo "secret=hidden"
echo "env=${FUZZPOOL_LEAK_CHECK:-clean}"
touch /usr/x 2>/dev/null && echo "usr=writable" || echo "usr=readonly"
echo ok > out && echo "workdir=writable"
`
	out, err := b.Command(context.Background(), Spec{Workdir: dir, Argv: []string{"/bin/sh", "-c", script}}).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	for _, want := range []string{"ifaces=lo,", "secret=hidden", "env=clean", "usr=readonly", "workdir=writable"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in sandbox output:\n%s", want, got)
		}
	}
}

func TestBwrapArgsLimits(t *testing.T) {
	args := Bwrap{MemoryBytes: 1 << 30, CPUSeconds: 10}.Args(Spec{Workdir: "/w", Env: []string{"A=b=c"}, Argv: []string{"/t", "in"}})
	joined := strings.Join(args, " ")
	for _, want := range []string{"--unshare-all", "--setenv A b=c", "-- prlimit --as=1073741824 --cpu=10 -- /t in"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}
