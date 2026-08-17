// Package server manages the public-facing HTTP(S) listeners: binding,
// TLS, and graceful shutdown.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/jameslauhe/go-firewall/internal/config"
)

// Server owns one *http.Server per configured listener.
type Server struct {
	servers   []*http.Server
	listeners []net.Listener
	ready     chan struct{}
}

func New(listeners []config.ListenConfig, handler http.Handler) (*Server, error) {
	if len(listeners) == 0 {
		return nil, fmt.Errorf("server: at least one listener is required")
	}

	s := &Server{ready: make(chan struct{})}
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

// Ready is closed once every listener has bound its socket (before Start
// begins serving), so callers using an ephemeral port (":0") know when
// Addrs() is safe to read.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Addrs returns each listener's actual bound address, in listener order.
// Only meaningful after Ready() is closed.
func (s *Server) Addrs() []string {
	addrs := make([]string, len(s.listeners))
	for i, ln := range s.listeners {
		addrs[i] = ln.Addr().String()
	}
	return addrs
}

// Start binds every listener, then serves them until Shutdown is called or
// one returns a non-shutdown error.
func (s *Server) Start() error {
	for _, hs := range s.servers {
		ln, err := net.Listen("tcp", hs.Addr)
		if err != nil {
			return fmt.Errorf("server: listen on %s: %w", hs.Addr, err)
		}
		s.listeners = append(s.listeners, ln)
	}
	close(s.ready)

	errCh := make(chan error, len(s.servers))
	for i, hs := range s.servers {
		hs, ln := hs, s.listeners[i]
		go func() {
			var err error
			if hs.TLSConfig != nil {
				// ServeTLS (not a manually tls.NewListener-wrapped
				// Serve) is required for Go's http.Server to wire up
				// its automatic HTTP/2 support — that wiring happens
				// inside ServeTLS/ListenAndServeTLS specifically, not
				// for a plain Serve() over an already-TLS listener.
				// Cert/key are already loaded into hs.TLSConfig, so no
				// file paths are needed here.
				err = hs.ServeTLS(ln, "", "")
			} else {
				err = hs.Serve(ln)
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
