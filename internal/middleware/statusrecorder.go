package middleware

import "net/http"

// StatusRecorder wraps an http.ResponseWriter to capture the status code
// and byte count actually written, for use by outer instrumentation
// middlewares (access logging, metrics) that need to observe the final
// response regardless of which inner middleware produced it.
type StatusRecorder struct {
	http.ResponseWriter
	Status int
	Bytes  int64
	wrote  bool
}

func WrapStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
}

func (sr *StatusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.Status = code
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *StatusRecorder) Write(b []byte) (int, error) {
	sr.wrote = true
	n, err := sr.ResponseWriter.Write(b)
	sr.Bytes += int64(n)
	return n, err
}
