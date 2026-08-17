package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusRecorder_DefaultsTo200IfWriteWithoutWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := WrapStatusRecorder(rec)

	n, err := sr.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned n = %d, want 5", n)
	}
	if sr.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200 (implicit)", sr.Status)
	}
	if sr.Bytes != 5 {
		t.Errorf("Bytes = %d, want 5", sr.Bytes)
	}
}

func TestStatusRecorder_CapturesExplicitStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := WrapStatusRecorder(rec)

	sr.WriteHeader(http.StatusForbidden)
	sr.Write([]byte("blocked"))

	if sr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", sr.Status)
	}
	if sr.Bytes != 7 {
		t.Errorf("Bytes = %d, want 7", sr.Bytes)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("underlying ResponseRecorder.Code = %d, want 403", rec.Code)
	}
}

func TestStatusRecorder_FirstWriteHeaderWins(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := WrapStatusRecorder(rec)

	sr.WriteHeader(http.StatusForbidden)
	sr.WriteHeader(http.StatusTeapot) // superfluous; must not change sr.Status

	if sr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403 (first WriteHeader call wins)", sr.Status)
	}
}

func TestStatusRecorder_AccumulatesMultipleWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := WrapStatusRecorder(rec)

	sr.Write([]byte("abc"))
	sr.Write([]byte("de"))

	if sr.Bytes != 5 {
		t.Errorf("Bytes = %d, want 5", sr.Bytes)
	}
}
