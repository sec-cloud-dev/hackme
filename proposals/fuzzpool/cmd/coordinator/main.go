// Command coordinator serves the fuzzpool API.
//
//	FUZZPOOL_ADMIN_TOKEN=secret coordinator -listen 127.0.0.1:8090 \
//	    -target-bin ./target -showmap "$(command -v afl-showmap)"
//
// The built-in "tinyparse" target is always registered for demos.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fuzzpool/internal/coordinator"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/sandbox"
	"fuzzpool/internal/target"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "address to serve on")
	bin := flag.String("target-bin", "", "sanitizer + AFL-instrumented fuzz target, registered as target \"bin\"")
	showmap := flag.String("showmap", "", "afl-showmap path; without it -target-bin is verified for crashes only")
	lfBuild := flag.String("libfuzzer-build", "", "optional libFuzzer build of the same source that workers may run")
	sb := flag.String("sandbox", "bwrap", "bwrap, or none (trusted local testing only)")
	timeout := flag.Duration("exec-timeout", 5*time.Second, "replay timeout per input")
	cpu := flag.Uint64("cpu-seconds", 10, "CPU limit per replay (bwrap only)")
	flag.Parse()

	token := os.Getenv("FUZZPOOL_ADMIN_TOKEN")
	if token == "" {
		log.Fatal("FUZZPOOL_ADMIN_TOKEN must be set")
	}
	var runner sandbox.Runner
	switch *sb {
	case "bwrap":
		// No RLIMIT_AS: ASan reserves terabytes of virtual memory and breaks
		// under it. Cap memory with a cgroup instead (see README).
		runner = sandbox.Bwrap{CPUSeconds: *cpu}
	case "none":
		log.Print("WARNING: replaying inputs without a sandbox")
		runner = sandbox.Direct{}
	default:
		log.Fatalf("unknown -sandbox %q", *sb)
	}

	targets := map[string]target.Executor{"tinyparse": target.TinyParse{}}
	builds := map[string]map[string]string{}
	if *bin != "" {
		b, err := target.OpenBinary(*bin, *showmap, *timeout, runner)
		if err != nil {
			log.Fatal(err)
		}
		targets["bin"] = b
		log.Printf("target \"bin\": %s %s (coverage replay: %v)", b.Path, b.Digest(), *showmap != "")
		if *lfBuild != "" {
			lf, err := target.OpenBinary(*lfBuild, "", 0, nil)
			if err != nil {
				log.Fatal(err)
			}
			builds["bin"] = map[string]string{"libfuzzer": lf.Digest()}
			log.Printf("libFuzzer worker build pinned: %s", lf.Digest())
		}
	}

	cfg := coordinator.DefaultConfig()
	cfg.ExecTimeout = *timeout
	led := ledger.New()
	srv := &coordinator.Server{Coord: coordinator.New(cfg, led), Ledger: led, AdminToken: token, Targets: targets, Builds: builds}
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	log.Printf("coordinator listening on %s", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
