package middleware

import (
	"bytes"
	"net/http"
	"time"

	"github.com/risedphantom/mcp-oauth2-proxy/utils/httplog"
	log "github.com/sirupsen/logrus"
)

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	status        int
	bytesWritten  int
	wroteHeader   bool
	captureBody   bool
	bodyBuf       bytes.Buffer
	bodyTruncated bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
		if rw.captureBody && !httplog.IsJSONContent(rw.Header().Get("Content-Type")) {
			rw.captureBody = false
		}
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	if rw.captureBody && !rw.bodyTruncated {
		remaining := httplog.MaxBodyLogSize - rw.bodyBuf.Len()
		if remaining <= 0 {
			rw.bodyTruncated = true
		} else if n <= remaining {
			rw.bodyBuf.Write(b[:n])
		} else {
			rw.bodyBuf.Write(b[:remaining])
			rw.bodyTruncated = true
		}
	}
	return n, err
}

// Flush implements http.Flusher, required for SSE streaming with FlushInterval: -1.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter, allowing http.ResponseController
// and similar helpers to access optional interfaces (e.g. http.Hijacker).
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// structuredLogger abstracts logrus structured logging so tests can capture
// fields without touching global state. The self-referential WithFields return
// type ensures chained calls (.WithFields().Debug()) go through the mock.
type structuredLogger interface {
	WithFields(fields log.Fields) structuredLogger
	Debug(args ...any)
}

// logrusAdapter wraps logrus.FieldLogger to satisfy structuredLogger.
type logrusAdapter struct {
	fl log.FieldLogger
}

func (a *logrusAdapter) WithFields(fields log.Fields) structuredLogger {
	return &logrusAdapter{fl: a.fl.WithFields(fields)}
}

func (a *logrusAdapter) Debug(args ...any) {
	a.fl.Debug(args...)
}

// LoggingMiddleware logs request and response metadata at Debug level.
type LoggingMiddleware struct {
	next      http.Handler
	logger    structuredLogger
	skipPaths map[string]struct{}
}

// NewLoggingMiddleware creates a LoggingMiddleware wrapping the given handler.
// Requests to any of the provided skipPaths are passed through without logging.
func NewLoggingMiddleware(next http.Handler, skipPaths ...string) *LoggingMiddleware {
	sp := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		sp[p] = struct{}{}
	}
	return &LoggingMiddleware{
		next:      next,
		logger:    &logrusAdapter{fl: log.StandardLogger()},
		skipPaths: sp,
	}
}

// newLoggingMiddlewareWithLogger creates a LoggingMiddleware with a custom logger.
// Used by unit tests to inject a mock logger.
func newLoggingMiddlewareWithLogger(next http.Handler, logger structuredLogger, skipPaths ...string) *LoggingMiddleware {
	sp := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		sp[p] = struct{}{}
	}
	return &LoggingMiddleware{next: next, logger: logger, skipPaths: sp}
}

// ServeHTTP logs request entry and response completion at Debug level.
// Requests matching a skip path are forwarded without logging.
func (m *LoggingMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, skip := m.skipPaths[r.URL.Path]; skip {
		m.next.ServeHTTP(w, r)
		return
	}

	start := time.Now()

	reqFields := log.Fields{
		"method":          r.Method,
		"path":            r.URL.Path,
		"remote_addr":     r.RemoteAddr,
		"request_headers": httplog.HeaderMap(r.Header),
	}

	snippet, body := httplog.CaptureBody(r.Body, r.Header.Get("Content-Type"))
	r.Body = body
	if snippet != nil {
		reqFields["request_body"] = snippet.Content
		if snippet.Truncated {
			reqFields["request_body_truncated"] = true
		}
	}

	m.logger.WithFields(reqFields).Debug("Request received")

	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK, captureBody: true}
	m.next.ServeHTTP(rw, r)

	respFields := log.Fields{
		"method":           r.Method,
		"path":             r.URL.Path,
		"status":           rw.status,
		"duration_ms":      time.Since(start).Milliseconds(),
		"bytes_written":    rw.bytesWritten,
		"response_headers": httplog.HeaderMap(w.Header()),
	}

	if rw.captureBody && rw.bodyBuf.Len() > 0 {
		respFields["response_body"] = rw.bodyBuf.String()
		if rw.bodyTruncated {
			respFields["response_body_truncated"] = true
		}
	}

	m.logger.WithFields(respFields).Debug("Response completed")
}
