// Command perimeter is a self-hosted monitor for a company's internet-facing assets.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/z6il/perimeter/internal/monitor"
	"github.com/z6il/perimeter/internal/store"
	"github.com/z6il/perimeter/internal/web"
)

var version = ""

func getVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", env("PERIMETER_ADDR", ":8080"), "address to listen on")
	data := flag.String("data", env("PERIMETER_DATA", "data"), "folder for the database")
	showVersion := flag.Bool("version", false, "print the version and exit")
	health := flag.Bool("healthcheck", false, "exit 0 if the server at -addr answers /healthz (for container health checks)")
	flag.Parse()
	if *showVersion {
		fmt.Println("perimeter", getVersion())
		return
	}
	if *health {
		os.Exit(healthcheck(*addr))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*addr, *data, log); err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}

func healthcheck(addr string) int {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + host + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		return 1
	}
	resp.Body.Close()
	return 0
}

func run(addr, dataDir string, log *slog.Logger) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "perimeter.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	generated, err := web.EnsurePassword(ctx, st, os.Getenv("PERIMETER_PASSWORD"))
	if err != nil {
		return err
	}
	if generated != "" {
		fmt.Fprintf(os.Stderr, "\n  First start. Sign in with this password (change it in Settings):\n\n      %s\n\n", generated)
	}

	mon := monitor.New(st, log)
	srv, err := web.New(st, mon, log, getVersion())
	if err != nil {
		return err
	}
	go mon.Loop(ctx)

	hs := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("perimeter is running", "addr", addr, "version", getVersion())

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}
