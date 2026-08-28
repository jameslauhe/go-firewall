// Command go-firewall is an L7 reverse-proxy / WAF that sits in front of a
// downstream gateway.
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
	"syscall"

	"github.com/jameslauhe/go-firewall/internal/admin"
	"github.com/jameslauhe/go-firewall/internal/config"
	accesslog "github.com/jameslauhe/go-firewall/internal/log"
	"github.com/jameslauhe/go-firewall/internal/metrics"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/ratelimit"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
	"github.com/jameslauhe/go-firewall/internal/netmatch"
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

	if err := run(*configPath, cfg); err != nil {
		slog.Error("go-firewall exited with error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, cfg *config.Config) error {
	slog.Info("starting go-firewall", "version", version.Version, "commit", version.Commit)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	trustedProxies, err := netmatch.NewMatcher(cfg.ClientIP.TrustedProxies)
	if err != nil {
		return err
	}

	mws := []mw.Middleware{
		mw.AttachRecorder,
		mw.ResolveClientIP(trustedProxies),
		accessLog.Middleware(),
		m.Middleware(),
		ipFilter.Middleware(),
		rateLimiter.Middleware(),
	}

	var wafEngine *waf.Engine
	if cfg.WAF.Enabled {
		wafEngine, err = waf.NewEngine(cfg.WAF)
		if err != nil {
			return err
		}
		mws = append(mws, wafEngine.Middleware())
	}

	go watchForReload(ctx, configPath, wafEngine, ipFilter, rateLimiter)

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

	var adminSrv *http.Server
	if cfg.Admin.Enabled {
		listeners := make([]string, len(cfg.Listen))
		for i, l := range cfg.Listen {
			listeners[i] = l.Address
		}
		adminServer, err := admin.New(cfg.Admin, admin.Info{
			Version:   version.Version,
			Listeners: listeners,
			Upstreams: cfg.Upstreams.Addresses,
		}, accessLog, ipFilter, wafEngine)
		if err != nil {
			return err
		}
		adminSrv = &http.Server{Addr: cfg.Admin.Address, Handler: adminServer.Handler()}
		go func() {
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("admin server exited unexpectedly", "error", err)
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()
	go func() {
		<-srv.Ready()
		slog.Info("listening", "addrs", srv.Addrs())
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
		if adminSrv != nil {
			_ = adminSrv.Shutdown(shutdownCtx)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// watchForReload reloads the WAF ruleset, IP lists, and rate limits on
// SIGHUP, until ctx is canceled. A failed reload logs and leaves every
// component serving its previous state — see reloadOnce.
func watchForReload(ctx context.Context, configPath string, wafEngine *waf.Engine, ipFilter *ipfilter.Filter, rateLimiter *ratelimit.Limiter) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	for {
		select {
		case <-sighup:
			if err := reloadOnce(configPath, wafEngine, ipFilter, rateLimiter); err != nil {
				slog.Error("config reload failed, keeping previous state", "error", err)
				continue
			}
			slog.Info("config reloaded")
		case <-ctx.Done():
			return
		}
	}
}

// reloadOnce reloads the WAF ruleset, IP lists, and rate limits from
// configPath's file. The new config is loaded and fully validated
// (config.Load) before any live component is touched, so a malformed new
// config never gets partway applied. Listener addresses, TLS, upstream
// addresses, and admin/metrics addresses are intentionally not re-read —
// changing those requires a process restart.
//
// Applying WAF, then ip lists, then rate limits is not a full staged
// multi-object transaction: a failure reloading ip lists after WAF has
// already reloaded would leave WAF on the new rules and ip lists/rate
// limits on the old ones. That residual window requires a config file
// that already passed full validation to then fail purely on a
// downstream component's own rebuild, which config.Load's Validate call
// is designed to rule out before reloadOnce ever touches a live
// component — see the config package's Validate for what's checked
// (including, since this feature, ip_lists.geo.db_path's existence).
func reloadOnce(configPath string, wafEngine *waf.Engine, ipFilter *ipfilter.Filter, rateLimiter *ratelimit.Limiter) error {
	newCfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if wafEngine != nil {
		if err := wafEngine.Reload(newCfg.WAF.RulesFile); err != nil {
			return fmt.Errorf("reload waf rules: %w", err)
		}
	}
	if err := ipFilter.Reload(newCfg.IPLists); err != nil {
		return fmt.Errorf("reload ip lists: %w", err)
	}
	rateLimiter.Reload(newCfg.RateLimit)

	return nil
}
