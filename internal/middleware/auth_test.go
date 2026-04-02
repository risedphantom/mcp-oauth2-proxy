package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
)

func testAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		BaseURL:              "https://mcp-proxy.example.com",
		AuthorizationServers: []string{"https://auth.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
	}
}

func TestAuthMiddleware_NoToken_Returns401(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called without token")
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("expected resource_metadata in WWW-Authenticate, got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `scope="mcp:read mcp:write"`) {
		t.Errorf("expected scope in WWW-Authenticate, got %q", wwwAuth)
	}
	// Should NOT contain error= when no token provided
	if strings.Contains(wwwAuth, "error=") {
		t.Errorf("expected no error= when token missing, got %q", wwwAuth)
	}
}

func TestAuthMiddleware_ValidToken_CallsNext(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NonBearerAuth_Returns401(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called with non-Bearer auth")
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Upstream401_RewritesChallenge(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("upstream body"))
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("expected error=invalid_token in WWW-Authenticate, got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("expected resource_metadata in WWW-Authenticate, got %q", wwwAuth)
	}

	if body := rec.Body.String(); body != "" {
		t.Errorf("expected empty body (upstream body suppressed), got %q", body)
	}
}

func TestAuthMiddleware_Upstream403_RewritesChallenge(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("upstream forbidden"))
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="insufficient_scope"`) {
		t.Errorf("expected error=insufficient_scope in WWW-Authenticate, got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("expected resource_metadata in WWW-Authenticate, got %q", wwwAuth)
	}

	if body := rec.Body.String(); body != "" {
		t.Errorf("expected empty body (upstream body suppressed), got %q", body)
	}
}

func TestAuthMiddleware_Upstream200_PassesThrough(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})

	m := NewAuthMiddleware(next, testAuthConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if wwwAuth := rec.Header().Get("WWW-Authenticate"); wwwAuth != "" {
		t.Errorf("expected no WWW-Authenticate header, got %q", wwwAuth)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Errorf("expected body 'hello', got %q", body)
	}
}

func TestAuthMiddleware_NoScopesConfigured(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := testAuthConfig()
	cfg.ScopesSupported = nil
	m := NewAuthMiddleware(next, cfg, nil)

	// With token — should call next
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Without token — WWW-Authenticate should not include scope
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	m.ServeHTTP(rec2, req2)

	wwwAuth := rec2.Header().Get("WWW-Authenticate")
	if strings.Contains(wwwAuth, "scope=") {
		t.Errorf("expected no scope in WWW-Authenticate when no scopes configured, got %q", wwwAuth)
	}
}
