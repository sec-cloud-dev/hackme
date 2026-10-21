// Package sandbox runs untrusted fuzz targets. Workers execute customer code
// and the coordinator executes worker-supplied inputs, so on both sides the
// target gets no network, no view of $HOME and only one writable directory.
package sandbox

import (
	"context"
	"os/exec"
	"strconv"
	"time"
)

type Spec struct {
	Workdir  string   // the only writable host path; also the working directory
	ReadOnly []string // extra host paths exposed read-only at the same location
	Env      []string // KEY=VALUE; nothing else from the host environment leaks in
	Argv     []string
}

type Runner interface {
	Command(ctx context.Context, s Spec) *exec.Cmd
}

const basePath = "PATH=/usr/local/bin:/usr/bin:/bin"

// Direct runs commands without isolation. Only for tests and trusted builds.
type Direct struct{}

func (Direct) Command(ctx context.Context, s Spec) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.Argv[0], s.Argv[1:]...)
	cmd.Dir = s.Workdir
	cmd.Env = append([]string{basePath}, s.Env...)
	cmd.WaitDelay = time.Second
	return cmd
}

// Bwrap isolates with bubblewrap: all namespaces unshared (so no network and
// no host processes), read-only system directories, a private /tmp, and
// optional address-space and CPU limits through prlimit.
type Bwrap struct {
	Path        string // bwrap binary; "" means "bwrap" from PATH
	MemoryBytes uint64
	CPUSeconds  uint64
}

func (b Bwrap) Args(s Spec) []string {
	args := []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
	}
	for _, kv := range s.Env {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				args = append(args, "--setenv", kv[:i], kv[i+1:])
				break
			}
		}
	}
	for _, p := range s.ReadOnly {
		args = append(args, "--ro-bind", p, p)
	}
	args = append(args, "--bind", s.Workdir, s.Workdir, "--chdir", s.Workdir, "--")
	if b.MemoryBytes > 0 || b.CPUSeconds > 0 {
		args = append(args, "prlimit")
		if b.MemoryBytes > 0 {
			args = append(args, "--as="+strconv.FormatUint(b.MemoryBytes, 10))
		}
		if b.CPUSeconds > 0 {
			args = append(args, "--cpu="+strconv.FormatUint(b.CPUSeconds, 10))
		}
		args = append(args, "--")
	}
	return append(args, s.Argv...)
}

func (b Bwrap) Command(ctx context.Context, s Spec) *exec.Cmd {
	path := b.Path
	if path == "" {
		path = "bwrap"
	}
	cmd := exec.CommandContext(ctx, path, b.Args(s)...)
	cmd.Dir = s.Workdir
	cmd.WaitDelay = time.Second
	return cmd
}
