package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
)

func startTestServer(t *testing.T, listeners []config.ListenConfig, handler http.Handler) *Server {
	t.Helper()
	srv, err := New(listeners, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	select {
	case <-srv.Ready():
	case err := <-errCh:
		t.Fatalf("server exited before becoming ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to become ready")
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	return srv
}

func TestServer_GracefulShutdown_DrainsInFlightRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	requestCompleted := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusOK)
		close(requestCompleted)
	})

	srv := startTestServer(t, []config.ListenConfig{{Address: "127.0.0.1:0"}}, handler)
	addr := srv.Addrs()[0]

	// Fire a slow request and wait for the handler to actually start.
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	select {
	case <-requestStarted:
	case err := <-errCh:
		t.Fatalf("request failed before handler started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handler to start")
	}

	// Begin shutdown while the request is still in flight.
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()

	// A new connection attempted during drain should be refused, not hang.
	time.Sleep(50 * time.Millisecond)
	if _, err := http.Get("http://" + addr + "/"); err == nil {
		t.Error("expected new connections to be refused during graceful shutdown")
	}

	// Let the in-flight request finish.
	close(releaseRequest)

	select {
	case <-requestCompleted:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	select {
	case resp := <-respCh:
		if resp.StatusCode != http.StatusOK {
			t.Errorf("in-flight request status = %d, want 200", resp.StatusCode)
		}
		resp.Body.Close()
	case err := <-errCh:
		t.Fatalf("in-flight request errored instead of completing: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for in-flight request's response")
	}

	if err := <-shutdownDone; err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

func TestServer_MultipleListeners(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := startTestServer(t, []config.ListenConfig{
		{Address: "127.0.0.1:0"},
		{Address: "127.0.0.1:0"},
	}, handler)

	addrs := srv.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("Addrs() = %v, want 2 entries", addrs)
	}
	if addrs[0] == addrs[1] {
		t.Fatal("expected two distinct ephemeral ports")
	}

	for _, addr := range addrs {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", addr, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", addr, resp.StatusCode)
		}
	}
}

func TestServer_TLS_HTTP2Negotiated(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert(t)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	certFile, keyFile := writeTempCertKey(t, certPEM, keyPEM)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
	})

	srv := startTestServer(t, []config.ListenConfig{{
		Address: "127.0.0.1:0",
		TLS:     config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
	}}, handler)
	addr := srv.Addrs()[0]

	cert, err := x509.ParseCertificate(mustParseFirstCertBlock(t, certPEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost"},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("negotiated protocol = %q (ProtoMajor %d), want HTTP/2", resp.Proto, resp.ProtoMajor)
	}
}
