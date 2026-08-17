// Command go-firewall is an L7 reverse-proxy / WAF that sits in front of a
// downstream gateway.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/proxy"
	"github.com/jameslauhe/go-firewall/internal/server"
	"github.com/jameslauhe/go-firewall/internal/version"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if err := run(cfg); err != nil {
		slog.Error("go-firewall exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	slog.Info("starting go-firewall", "version", version.Version, "commit", version.Commit)

	p, err := proxy.New(cfg.Upstreams)
	if err != nil {
		return err
	}

	ipFilter, err := ipfilter.New(cfg.IPLists)
	if err != nil {
		return err
	}
	defer ipFilter.Close()

	handler := mw.Chain(p.Handler(),
		mw.AttachRecorder,
		ipFilter.Middleware(),
	)

	srv, err := server.New(cfg.Listen, handler)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining connections", "timeout", cfg.Shutdown.DrainTimeout.Duration)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.DrainTimeout.Duration)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("shutdown did not complete cleanly", "error", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
