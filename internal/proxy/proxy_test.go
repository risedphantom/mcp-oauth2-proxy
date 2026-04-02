package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
	"github.com/risedphantom/mcp-oauth2-proxy/utils/httplog"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

func TestNewProxy_ForwardsRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":"ok"}`)
	}))
	defer backend.Close()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if body != `{"jsonrpc":"2.0","id":1,"result":"ok"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestNewProxy_SSEStreaming(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}
		for i := range 3 {
			_, _ = fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer backend.Close()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", ct)
	}
	body := rec.Body.String()
	for i := range 3 {
		expected := fmt.Sprintf("data: event-%d", i)
		if !contains(body, expected) {
			t.Errorf("expected body to contain %q", expected)
		}
	}
}

func TestNewProxy_UpstreamDown(t *testing.T) {
	// Start and immediately close to get a port that refuses connections
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	backendURL := backend.URL
	backend.Close()

	p, err := NewProxy(config.UpstreamConfig{URL: backendURL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestNewProxy_PreservesPath(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/messages", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if receivedPath != "/api/v1/messages" {
		t.Errorf("expected path /api/v1/messages, got %s", receivedPath)
	}
}

func TestNewProxy_SSEStreamingRealHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}
		for i := range 3 {
			_, _ = fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer backend.Close()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Use a real HTTP server to test actual streaming behavior
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/sse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	for i := range 3 {
		expected := fmt.Sprintf("data: event-%d", i)
		if !contains(string(body), expected) {
			t.Errorf("expected body to contain %q", expected)
		}
	}
}

const upstreamResponseMsg = "Upstream response"

func TestModifyResponse_LogsUpstreamJSON(t *testing.T) {
	expectedBody := `{"jsonrpc":"2.0","id":1,"result":"hello"}`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, expectedBody)
	}))
	defer backend.Close()

	// Install a logrus test hook to capture log entries.
	hook := &test.Hook{}
	log.AddHook(hook)
	log.SetLevel(log.DebugLevel)
	defer func() {
		log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
		log.SetLevel(log.InfoLevel)
	}()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/test-path", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Verify client still receives the full response body.
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if rec.Body.String() != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, rec.Body.String())
	}

	// Find the "Upstream response" log entry.
	var found *log.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Message == upstreamResponseMsg {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatal("expected '" + upstreamResponseMsg + "' log entry, not found")
	}

	if status, ok := found.Data["upstream_status"]; !ok || status != http.StatusCreated {
		t.Errorf("expected upstream_status=201, got %v", found.Data["upstream_status"])
	}
	if urlPath, ok := found.Data["upstream_url"]; !ok || urlPath != "/test-path" {
		t.Errorf("expected upstream_url=/test-path, got %v", found.Data["upstream_url"])
	}
	if body, ok := found.Data["upstream_body"]; !ok || body != expectedBody {
		t.Errorf("expected upstream_body=%q, got %v", expectedBody, found.Data["upstream_body"])
	}
}

func TestModifyResponse_SkipsBodyForSSE(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "data: hello\n\n")
	}))
	defer backend.Close()

	hook := &test.Hook{}
	log.AddHook(hook)
	log.SetLevel(log.DebugLevel)
	defer func() {
		log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
		log.SetLevel(log.InfoLevel)
	}()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	var found *log.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Message == upstreamResponseMsg {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatal("expected '" + upstreamResponseMsg + "' log entry, not found")
	}

	if _, ok := found.Data["upstream_body"]; ok {
		t.Error("expected no upstream_body for SSE response")
	}
}

func TestModifyResponse_TruncatesLargeBody(t *testing.T) {
	// Build a JSON body larger than maxBodyLogSize.
	largeBody := `{"data":"` + strings.Repeat("x", httplog.MaxBodyLogSize+100) + `"}`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, largeBody)
	}))
	defer backend.Close()

	hook := &test.Hook{}
	log.AddHook(hook)
	log.SetLevel(log.DebugLevel)
	defer func() {
		log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
		log.SetLevel(log.InfoLevel)
	}()

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Client must still receive the full body.
	if rec.Body.String() != largeBody {
		t.Error("client did not receive the full body")
	}

	var found *log.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Message == upstreamResponseMsg {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatal("expected '" + upstreamResponseMsg + "' log entry, not found")
	}

	body, ok := found.Data["upstream_body"].(string)
	if !ok {
		t.Fatal("upstream_body not a string")
	}
	if len(body) != httplog.MaxBodyLogSize {
		t.Errorf("expected logged body len=%d, got %d", httplog.MaxBodyLogSize, len(body))
	}
	if trunc, ok := found.Data["upstream_body_truncated"]; !ok || trunc != true {
		t.Error("expected upstream_body_truncated=true")
	}
}

// headerCapturingBackend returns an httptest.Server that records the headers
// it receives and a pointer to retrieve them.
func headerCapturingBackend(t *testing.T) (*httptest.Server, *http.Header) {
	t.Helper()
	var received http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	return backend, &received
}

func TestNewProxy_RemovesHeaders(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionRemove, Name: "X-Unwanted"},
			{Action: config.MutationActionRemove, Name: "X-Remove-Me"},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Unwanted", "bad")
	req.Header.Set("X-Remove-Me", "also-bad")
	req.Header.Set("X-Keep", "good")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Unwanted") != "" {
		t.Errorf("expected X-Unwanted to be removed")
	}
	if received.Get("X-Remove-Me") != "" {
		t.Errorf("expected X-Remove-Me to be removed")
	}
	if received.Get("X-Keep") != "good" {
		t.Errorf("expected X-Keep=good, got %s", received.Get("X-Keep"))
	}
}

func TestNewProxy_AddsStaticHeaders(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionAdd, Name: "X-Custom", Value: "value"},
			{Action: config.MutationActionAdd, Name: "X-Forwarded-By", Value: "mcp-oauth2-proxy"},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if received.Get("X-Custom") != "value" {
		t.Errorf("expected X-Custom=value, got %s", received.Get("X-Custom"))
	}
	if received.Get("X-Forwarded-By") != "mcp-oauth2-proxy" {
		t.Errorf("expected X-Forwarded-By=mcp-oauth2-proxy, got %s", received.Get("X-Forwarded-By"))
	}
}

func TestNewProxy_AddFromRequestHeader(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionAdd, Name: "X-Copied", ValueFrom: &config.ValueFrom{RequestHeader: "X-Source"}},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	req.Header.Set("X-Source", "source-value")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Copied") != "source-value" {
		t.Errorf("expected X-Copied=source-value, got %s", received.Get("X-Copied"))
	}
}

func TestNewProxy_AddFromQueryParameter(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionAdd, Name: "X-Token", ValueFrom: &config.ValueFrom{QueryParameter: "token"}},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/?token=abc123", nil))

	if received.Get("X-Token") != "abc123" {
		t.Errorf("expected X-Token=abc123, got %s", received.Get("X-Token"))
	}
}

func TestNewProxy_MutationOrderingMatters(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionRemove, Name: "X-Target"},
			{Action: config.MutationActionAdd, Name: "X-Target", Value: "new-value"},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Target", "old-value")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Target") != "new-value" {
		t.Errorf("expected X-Target=new-value, got %s", received.Get("X-Target"))
	}
}

func TestNewProxy_EmptyMutations(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Existing", "value")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Existing") != "value" {
		t.Errorf("expected X-Existing=value, got %s", received.Get("X-Existing"))
	}
}

func TestNewProxy_DoesNotMutateOriginalRequest(t *testing.T) {
	backend, _ := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionAdd, Name: "X-Added", Value: "yes"},
			{Action: config.MutationActionRemove, Name: "X-Original"},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Original", "present")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if req.Header.Get("X-Original") != "present" {
		t.Error("original request was mutated")
	}
	if req.Header.Get("X-Added") != "" {
		t.Error("original request was mutated with added header")
	}
}

func TestNewProxy_ValueFromReadsOriginalRequest(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionRemove, Name: "X-Source"},
			{Action: config.MutationActionAdd, Name: "X-Copied", ValueFrom: &config.ValueFrom{RequestHeader: "X-Source"}},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Source", "original-value")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Source") != "" {
		t.Errorf("expected X-Source to be removed, got %s", received.Get("X-Source"))
	}
	if received.Get("X-Copied") != "original-value" {
		t.Errorf("expected X-Copied=original-value, got %s", received.Get("X-Copied"))
	}
}

func TestNewProxy_SetXForwarded(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionSetXForwarded},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Forwarded-For") == "" {
		t.Error("expected X-Forwarded-For to be set")
	}
	if received.Get("X-Forwarded-Host") == "" {
		t.Error("expected X-Forwarded-Host to be set")
	}
	if received.Get("X-Forwarded-Proto") == "" {
		t.Error("expected X-Forwarded-Proto to be set")
	}
}

func TestNewProxy_NoSetXForwardedByDefault(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	// Empty mutations — no set-x-forwarded action.
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, config.HeadersConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)

	if received.Get("X-Forwarded-For") != "" {
		t.Error("expected X-Forwarded-For to NOT be set without set-x-forwarded action")
	}
	if received.Get("X-Forwarded-Host") != "" {
		t.Error("expected X-Forwarded-Host to NOT be set without set-x-forwarded action")
	}
	if received.Get("X-Forwarded-Proto") != "" {
		t.Error("expected X-Forwarded-Proto to NOT be set without set-x-forwarded action")
	}
}

func TestNewProxy_ValueFromMissingSource(t *testing.T) {
	backend, received := headerCapturingBackend(t)

	hCfg := config.HeadersConfig{
		Mutations: []config.HeaderMutation{
			{Action: config.MutationActionAdd, Name: "X-Missing-Header", ValueFrom: &config.ValueFrom{RequestHeader: "X-Nonexistent"}},
			{Action: config.MutationActionAdd, Name: "X-Missing-Query", ValueFrom: &config.ValueFrom{QueryParameter: "nonexistent"}},
		},
	}
	p, err := NewProxy(config.UpstreamConfig{URL: backend.URL}, hCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if received.Get("X-Missing-Header") != "" {
		t.Errorf("expected empty string for missing header source, got %s", received.Get("X-Missing-Header"))
	}
	if received.Get("X-Missing-Query") != "" {
		t.Errorf("expected empty string for missing query source, got %s", received.Get("X-Missing-Query"))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
