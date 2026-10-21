package target

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"fuzzpool/internal/coverage"
)

var (
	frameRe     = regexp.MustCompile(`^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+)`)
	asanRe      = regexp.MustCompile(`ERROR: AddressSanitizer: ([A-Za-z0-9_-]+)`)
	msanRe      = regexp.MustCompile(`WARNING: MemorySanitizer: ([A-Za-z0-9_-]+)`)
	libfuzzerRe = regexp.MustCompile(`ERROR: libFuzzer: ([a-z][a-z -]*[a-z])`)
	ubsanRe     = regexp.MustCompile(`runtime error: `)
)

// Frames from the sanitizer runtime, libc and the fuzzing driver describe
// how the crash was reported, not where the bug is.
var noiseFramePrefixes = []string{
	"__asan", "__interceptor", "___interceptor", "__sanitizer", "__ubsan", "__msan", "__lsan",
	"fuzzer::", "__libc", "__GI_", "abort", "raise", "_start", "std::__",
}

// ParseSanitizerReport extracts a crash from ASan/MSan/UBSan/libFuzzer
// output. It returns nil when the output contains no crash report, which is
// deliberate: an exit code alone is not a payable crash.
func ParseSanitizerReport(report []byte) *Crash {
	text := string(report)
	var kind string
	if m := asanRe.FindStringSubmatch(text); m != nil {
		kind = "asan:" + m[1]
	} else if m := msanRe.FindStringSubmatch(text); m != nil {
		kind = "msan:" + m[1]
	} else if ubsanRe.MatchString(text) {
		kind = "ubsan:runtime-error"
	} else if m := libfuzzerRe.FindStringSubmatch(text); m != nil {
		kind = "libfuzzer:" + strings.ReplaceAll(m[1], " ", "-")
	} else {
		return nil
	}
	var frames []string
	sc := bufio.NewScanner(bytes.NewReader(report))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(frames) < 3 {
		m := frameRe.FindStringSubmatch(sc.Text())
		if m == nil || isNoiseFrame(m[1]) {
			continue
		}
		frames = append(frames, m[1]+" "+shortLocation(m[2]))
	}
	return &Crash{Kind: kind, Signature: Signature(kind, frames), Frames: frames}
}

func isNoiseFrame(fn string) bool {
	for _, p := range noiseFramePrefixes {
		if strings.HasPrefix(fn, p) {
			return true
		}
	}
	return false
}

// shortLocation turns "/src/lib/parse.c:42:13" into "parse.c:42" so builds in
// different directories still agree on the signature.
func shortLocation(loc string) string {
	parts := strings.Split(path.Base(loc), ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return parts[0]
}

// ParseShowmap parses afl-showmap output: one "edge_id:hit_count" per line.
func ParseShowmap(data []byte) ([]coverage.Edge, error) {
	var edges []coverage.Edge
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		id, _, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("showmap: malformed line %q", line)
		}
		v, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("showmap: malformed edge id %q", id)
		}
		edges = append(edges, coverage.Edge(v))
	}
	return coverage.Normalize(edges), sc.Err()
}
