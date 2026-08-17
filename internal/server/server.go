// Package server manages the public-facing HTTP(S) listeners: binding,
// TLS, and graceful shutdown.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/jameslauhe/go-firewall/internal/config"
)

// Server owns one *http.Server per configured listener.
type Server struct {
	servers []*http.Server
}

func New(listeners []config.ListenConfig, handler http.Handler) (*Server, error) {
	if len(listeners) == 0 {
		return nil, fmt.Errorf("server: at least one listener is required")
	}

	s := &Server{}
	for _, l := range listeners {
		hs := &http.Server{
			Addr:    l.Address,
			Handler: handler,
		}
		if l.TLS.Enabled {
			cert, err := tls.LoadX509KeyPair(l.TLS.CertFile, l.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("server: load TLS cert for %s: %w", l.Address, err)
			}
			hs.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2", "http/1.1"},
			}
		}
		s.servers = append(s.servers, hs)
	}
	return s, nil
}

// Start binds and serves every listener. It blocks until the first
// listener returns a non-shutdown error, or returns nil once all listeners
// have been cleanly shut down via Shutdown.
func (s *Server) Start() error {
	errCh := make(chan error, len(s.servers))
	for _, hs := range s.servers {
		hs := hs
		go func() {
			var err error
			if hs.TLSConfig != nil {
				err = hs.ListenAndServeTLS("", "")
			} else {
				err = hs.ListenAndServe()
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}

	for range s.servers {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

// Shutdown gracefully drains every listener, bounded by ctx's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, hs := range s.servers {
		if err := hs.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
