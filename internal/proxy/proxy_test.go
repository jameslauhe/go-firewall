package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
)

func testUpstreamConfig(addrs ...string) config.UpstreamConfig {
	return config.UpstreamConfig{
		Addresses:             addrs,
		DialTimeout:           config.Duration{Duration: time.Second},
		ResponseHeaderTimeout: config.Duration{Duration: time.Second},
		IdleConnTimeout:       config.Duration{Duration: time.Second},
		MaxIdleConnsPerHost:   10,
	}
}

func TestProxy_ForwardsToUpstream(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From-Backend", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	p, err := New(testUpstreamConfig(backend.URL))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	front := httptest.NewServer(p.Handler())
	defer front.Close()

	resp, err := http.Get(front.URL + "/some/path")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-From-Backend") != "yes" {
		t.Errorf("missing backend header, got headers: %v", resp.Header)
	}
}

func TestProxy_NoUpstreamAddresses(t *testing.T) {
	if _, err := New(testUpstreamConfig()); err == nil {
		t.Fatal("expected error when no upstream addresses configured")
	}
}

func TestProxy_UpstreamDown(t *testing.T) {
	p, err := New(testUpstreamConfig("http://127.0.0.1:1")) // reserved, always refused
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	front := httptest.NewServer(p.Handler())
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestProxy_RoundRobinsAcrossUpstreams(t *testing.T) {
	hits := map[string]int{}
	newBackend := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[name]++
			w.WriteHeader(http.StatusOK)
		}))
	}
	b1 := newBackend("b1")
	defer b1.Close()
	b2 := newBackend("b2")
	defer b2.Close()

	p, err := New(testUpstreamConfig(b1.URL, b2.URL))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	front := httptest.NewServer(p.Handler())
	defer front.Close()

	for i := 0; i < 10; i++ {
		resp, err := http.Get(front.URL + "/")
		if err != nil {
			t.Fatalf("GET error: %v", err)
		}
		resp.Body.Close()
	}

	if hits["b1"] == 0 || hits["b2"] == 0 {
		t.Errorf("expected both backends to receive traffic, got %v", hits)
	}
}
