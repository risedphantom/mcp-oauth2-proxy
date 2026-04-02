package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/risedphantom/mcp-oauth2-proxy/utils/httplog"
	log "github.com/sirupsen/logrus"
)

// logEntry captures a single structured log call.
type logEntry struct {
	fields log.Fields
	msg    string
}

// mockLogger implements structuredLogger, capturing log entries for assertions.
type mockLogger struct {
	mu      sync.Mutex
	entries *[]logEntry
	fields  log.Fields
}

func newMockLogger() *mockLogger {
	return &mockLogger{entries: &[]logEntry{}}
}

func (m *mockLogger) WithFields(fields log.Fields) structuredLogger {
	return &mockLogger{
		entries: m.entries,
		fields:  fields,
	}
}

func (m *mockLogger) Debug(args ...any) {
	msg := ""
	if len(args) > 0 {
		msg, _ = args[0].(string)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.entries = append(*m.entries, logEntry{fields: m.fields, msg: msg})
}

func (m *mockLogger) getEntries() []logEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]logEntry, len(*m.entries))
	copy(cp, *m.entries)
	return cp
}

func findEntry(entries []logEntry, msg string) (logEntry, bool) {
	for _, e := range entries {
		if e.msg == msg {
			return e, true
		}
	}
	return logEntry{}, false
}

func TestLoggingMiddleware_LogsRequestFields(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodPost, "/test/path", nil)
	req.Header.Set("X-Custom", "value")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Request received")
	if !ok {
		t.Fatal("expected 'Request received' log entry")
	}
	if entry.fields["method"] != http.MethodPost {
		t.Errorf("expected method POST, got %v", entry.fields["method"])
	}
	if entry.fields["path"] != "/test/path" {
		t.Errorf("expected path /test/path, got %v", entry.fields["path"])
	}
	if entry.fields["request_headers"] == nil {
		t.Error("expected request_headers field to be set")
	}
}

func TestLoggingMiddleware_LogsResponseFields(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("hello")) //nolint:errcheck
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Response completed")
	if !ok {
		t.Fatal("expected 'Response completed' log entry")
	}
	if entry.fields["method"] != http.MethodGet {
		t.Errorf("expected method GET, got %v", entry.fields["method"])
	}
	if entry.fields["path"] != "/resource" {
		t.Errorf("expected path /resource, got %v", entry.fields["path"])
	}
	if entry.fields["status"] != http.StatusCreated {
		t.Errorf("expected status 201, got %v", entry.fields["status"])
	}
	if entry.fields["bytes_written"] != 5 {
		t.Errorf("expected bytes_written 5, got %v", entry.fields["bytes_written"])
	}
	if entry.fields["duration_ms"] == nil {
		t.Error("expected duration_ms field to be set")
	}
	if entry.fields["response_headers"] == nil {
		t.Error("expected response_headers field to be set")
	}
}

func TestLoggingMiddleware_PassesThrough(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.Header().Set("X-Response", "yes")
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("body")) //nolint:errcheck
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("expected status 418, got %d", rec.Code)
	}
	if rec.Body.String() != "body" {
		t.Errorf("expected body 'body', got %q", rec.Body.String())
	}
}

func TestLoggingMiddleware_ImplementsFlusher(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		} else {
			t.Error("expected responseWriter to implement http.Flusher")
		}
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
}

func TestLoggingMiddleware_DefaultStatus200(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write body without calling WriteHeader — should default to 200.
		w.Write([]byte("ok")) //nolint:errcheck
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	entry, ok := findEntry(ml.getEntries(), "Response completed")
	if !ok {
		t.Fatal("expected 'Response completed' log entry")
	}
	if entry.fields["status"] != http.StatusOK {
		t.Errorf("expected logged status 200, got %v", entry.fields["status"])
	}
}

// Helper unit tests for shared httplog functions have moved to utils/httplog/httplog_test.go.

// --- Request body logging tests ---

func TestLoggingMiddleware_LogsRequestBodyJSON(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	body := `{"jsonrpc":"2.0","method":"ping"}`
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Request received")
	if !ok {
		t.Fatal("expected 'Request received' log entry")
	}
	if entry.fields["request_body"] == nil {
		t.Fatal("expected request_body field")
	}
	if s, ok := entry.fields["request_body"].(string); !ok || s != body {
		t.Errorf("expected request_body %q, got %v", body, entry.fields["request_body"])
	}
	if entry.fields["request_body_truncated"] != nil {
		t.Error("did not expect request_body_truncated for small body")
	}
}

func TestLoggingMiddleware_SkipsRequestBodyNonJSON(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("plain text"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Request received")
	if !ok {
		t.Fatal("expected 'Request received' log entry")
	}
	if entry.fields["request_body"] != nil {
		t.Error("expected request_body to be absent for non-JSON content type")
	}
}

func TestLoggingMiddleware_RequestBodyTruncation(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	largeBody := strings.Repeat("x", httplog.MaxBodyLogSize+100)
	var downstreamBody []byte

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Request received")
	if !ok {
		t.Fatal("expected 'Request received' log entry")
	}
	if entry.fields["request_body"] == nil {
		t.Fatal("expected request_body field")
	}
	if entry.fields["request_body_truncated"] != true {
		t.Error("expected request_body_truncated to be true")
	}

	// Downstream must still receive the full body.
	if len(downstreamBody) != len(largeBody) {
		t.Errorf("downstream got %d bytes, want %d", len(downstreamBody), len(largeBody))
	}
}

// --- Response body logging tests ---

func TestLoggingMiddleware_LogsResponseBodyJSON(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	respBody := `{"result":"ok"}`
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(respBody)) //nolint:errcheck
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Response completed")
	if !ok {
		t.Fatal("expected 'Response completed' log entry")
	}
	if entry.fields["response_body"] == nil {
		t.Fatal("expected response_body field")
	}
	if s, ok := entry.fields["response_body"].(string); !ok || s != respBody {
		t.Errorf("expected response_body %q, got %v", respBody, entry.fields["response_body"])
	}
	if entry.fields["response_body_truncated"] != nil {
		t.Error("did not expect response_body_truncated for small body")
	}

	// Client still gets the full response.
	if rec.Body.String() != respBody {
		t.Errorf("client got %q, want %q", rec.Body.String(), respBody)
	}
}

func TestLoggingMiddleware_SkipsResponseBodyNonJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ct   string
	}{
		{"text/plain", "text/plain"},
		{"SSE", "text/event-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ml := newMockLogger()
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.ct)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("data: hello\n\n")) //nolint:errcheck
			})

			m := newLoggingMiddlewareWithLogger(next, ml)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			m.ServeHTTP(rec, req)

			entry, ok := findEntry(ml.getEntries(), "Response completed")
			if !ok {
				t.Fatal("expected 'Response completed' log entry")
			}
			if entry.fields["response_body"] != nil {
				t.Error("expected response_body to be absent for non-JSON content type")
			}
		})
	}
}

func TestLoggingMiddleware_ResponseBodyTruncation(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	largeResp := bytes.Repeat([]byte("a"), httplog.MaxBodyLogSize+200)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(largeResp) //nolint:errcheck
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	entry, ok := findEntry(ml.getEntries(), "Response completed")
	if !ok {
		t.Fatal("expected 'Response completed' log entry")
	}
	if entry.fields["response_body"] == nil {
		t.Fatal("expected response_body field")
	}
	if entry.fields["response_body_truncated"] != true {
		t.Error("expected response_body_truncated to be true")
	}

	// Client still gets the full response.
	if rec.Body.Len() != len(largeResp) {
		t.Errorf("client got %d bytes, want %d", rec.Body.Len(), len(largeResp))
	}
}

func TestLoggingMiddleware_DownstreamReadsFullBody(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	original := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	var downstream string

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("unexpected read error: %v", err)
		}
		downstream = string(b)
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(original))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if downstream != original {
		t.Errorf("downstream got %q, want %q", downstream, original)
	}
}

func TestLoggingMiddleware_SkipPaths(t *testing.T) {
	t.Parallel()

	ml := newMockLogger()
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	m := newLoggingMiddlewareWithLogger(next, ml, "/healthz", "/readyz")

	// Request to a skip path should not produce log entries.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called for skip path")
	}
	if len(ml.getEntries()) != 0 {
		t.Errorf("expected 0 log entries for skip path, got %d", len(ml.getEntries()))
	}

	// Request to a non-skip path should still be logged.
	nextCalled = false
	req = httptest.NewRequest(http.MethodGet, "/other", nil)
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called for non-skip path")
	}
	if len(ml.getEntries()) != 2 {
		t.Errorf("expected 2 log entries (request+response), got %d", len(ml.getEntries()))
	}
}
