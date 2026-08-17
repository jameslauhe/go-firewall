package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestProxy_WebSocketPassthrough verifies that httputil.ReverseProxy's
// built-in Upgrade handling passes a WebSocket connection through
// go-firewall's proxy layer transparently: raw bytes written by the client
// after the 101 handshake reach the backend and its echoed bytes reach the
// client, unmodified in both directions.
func TestProxy_WebSocketPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()

		// Echo loop: whatever bytes arrive get written straight back.
		chunk := make([]byte, 4096)
		for {
			n, err := buf.Reader.Read(chunk)
			if n > 0 {
				if _, werr := conn.Write(chunk[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}))
	defer backend.Close()

	p, err := New(testUpstreamConfig(backend.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(p.Handler())
	defer front.Close()

	frontURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatalf("parse front URL: %v", err)
	}

	conn, err := net.DialTimeout("tcp", frontURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "GET / HTTP/1.1\r\n" +
		"Host: " + frontURL.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 Switching Protocols", resp.StatusCode)
	}
	if resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("Upgrade header = %q, want websocket", resp.Header.Get("Upgrade"))
	}

	payload := []byte("hello-through-the-proxy")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echoed payload = %q, want %q", got, payload)
	}
}
