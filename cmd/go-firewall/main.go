// Command go-firewall is an L7 reverse-proxy / WAF that sits in front of a
// downstream gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jameslauhe/go-firewall/internal/config"
	accesslog "github.com/jameslauhe/go-firewall/internal/log"
	"github.com/jameslauhe/go-firewall/internal/metrics"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/ratelimit"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
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
	accesslog.ConfigureDefault(cfg.Log)

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

	rateLimiter := ratelimit.New(cfg.RateLimit)
	defer rateLimiter.Stop()

	accessLog, err := accesslog.New(cfg.Log)
	if err != nil {
		return err
	}
	defer accessLog.Close()

	m := metrics.New(cfg.Metrics.Path, rateLimiter.ActiveBuckets)

	mws := []mw.Middleware{
		mw.AttachRecorder,
		accessLog.Middleware(),
		m.Middleware(),
		ipFilter.Middleware(),
		rateLimiter.Middleware(),
	}

	if cfg.WAF.Enabled {
		wafEngine, err := waf.NewEngine(cfg.WAF)
		if err != nil {
			return err
		}
		mws = append(mws, wafEngine.Middleware())
	}

	handler := mw.Chain(p.Handler(), mws...)

	srv, err := server.New(cfg.Listen, handler)
	if err != nil {
		return err
	}

	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle(m.Path(), m.Handler())
		metricsSrv = &http.Server{Addr: cfg.Metrics.Address, Handler: mux}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics server exited unexpectedly", "error", err)
			}
		}()
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
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutdownCtx)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
