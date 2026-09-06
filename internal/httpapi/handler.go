// Package httpapi assembles the production HTTP handler chain.
//
// Extracted from cmd/submcp so golden parity tests can drive the SAME
// handler the deployed binary serves — including the request-logging
// wrapper. The P0-1.1 SSE 500s existed precisely because tests bypassed
// this chain (they called srv.Handler() directly, which lacks
// withRequestLogging's statusRecorder).
package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/subimpact/submcp/internal/mcp"
	"github.com/subimpact/submcp/internal/ui"
)

// Build assembles the root handler: admin UI at /, gateway routes,
// health/ready/metrics, all wrapped in request logging.
func Build(logger *slog.Logger, srv *mcp.Server, adminUI *ui.UI) http.Handler {
	root := http.NewServeMux()
	root.Handle("/", adminUI.Handler())
	root.Handle("/health", srv.Handler())
	root.Handle("/ready", srv.Handler())
	root.Handle("/metrics", srv.Handler())
	root.Handle("/metamcp/", srv.Handler())

	return withRequestLogging(logger, root)
}

// withRequestLogging wraps a handler with structured request logging.
func withRequestLogging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", r.RemoteAddr,
			"ua", r.UserAgent(),
		)
	})
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Flush implements http.Flusher so SSE streams survive the logging
// wrapper (P0-1.1: without this, both SSE endpoints 500 in production —
// the type assertion w.(http.Flusher) fails because the embedded
// interface does not promote Flush).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
