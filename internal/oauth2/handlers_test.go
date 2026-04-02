package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// computeS256Challenge computes the S256 PKCE challenge for a given verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func newTestHandlers(t *testing.T) (*Handlers, *Store) { //nolint:unparam
	t.Helper()

	// Mock Keycloak token endpoint
	kcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			grantType := r.PostFormValue("grant_type")
			w.Header().Set("Content-Type", "application/json")

			if grantType == "refresh_token" {
				rt := r.PostFormValue("refresh_token")
				if rt == "kc-invalid-refresh" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "Token is not active",
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "kc-refreshed-access-token",
					"token_type":    "Bearer",
					"expires_in":    300,
					"refresh_token": "kc-new-refresh-token",
				})
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "kc-access-token-xyz",
				"token_type":    "Bearer",
				"expires_in":    300,
				"refresh_token": "kc-refresh-token-xyz",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	store := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	t.Cleanup(func() {
		store.Close()
		kcServer.Close()
	})

	kcEndpoints := &KeycloakEndpoints{
		Issuer:                "https://auth.example.com/realms/test",
		AuthorizationEndpoint: "https://auth.example.com/realms/test/protocol/openid-connect/auth",
		TokenEndpoint:         kcServer.URL + "/token",
	}

	handlers := NewHandlers(store, kcEndpoints, "https://proxy.example.com", "proxy-client", "proxy-secret", []string{"openid", "mcp:read"}, []string{"openid", "profile", "email", "groups"}, []string{"https://auth.example.com/realms/test"})
	handlers.httpClient = kcServer.Client()

	return handlers, store
}

func TestHandleASMetadata(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	h.HandleASMetadata().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if meta["issuer"] != "https://proxy.example.com" {
		t.Errorf("unexpected issuer: %v", meta["issuer"])
	}
	if meta["authorization_endpoint"] != "https://proxy.example.com/oauth/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", meta["authorization_endpoint"])
	}
	if meta["token_endpoint"] != "https://proxy.example.com/oauth/token" {
		t.Errorf("unexpected token_endpoint: %v", meta["token_endpoint"])
	}
	if meta["registration_endpoint"] != "https://proxy.example.com/oauth/register" {
		t.Errorf("unexpected registration_endpoint: %v", meta["registration_endpoint"])
	}

	scopes, ok := meta["scopes_supported"].([]any)
	if !ok || len(scopes) != 2 {
		t.Errorf("unexpected scopes_supported: %v", meta["scopes_supported"])
	}

	grants, ok := meta["grant_types_supported"].([]any)
	if !ok || len(grants) != 2 {
		t.Fatalf("expected 2 grant types, got: %v", meta["grant_types_supported"])
	}
	if grants[0] != "authorization_code" || grants[1] != "refresh_token" {
		t.Errorf("unexpected grant_types_supported: %v", grants)
	}
}

func TestHandleRegister_Success(t *testing.T) {
	h, _ := newTestHandlers(t)

	body := `{"redirect_uris":["http://localhost:3000/callback"],"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRegister().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Error("expected client_id in response")
	}
	if resp["client_secret"] == nil || resp["client_secret"] == "" {
		t.Error("expected client_secret in response")
	}
	if resp["client_name"] != "test-app" {
		t.Errorf("unexpected client_name: %v", resp["client_name"])
	}
}

func TestHandleRegister_MissingRedirectURIs(t *testing.T) {
	h, _ := newTestHandlers(t)

	body := `{"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRegister().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRegister_InvalidRedirectURI(t *testing.T) {
	h, _ := newTestHandlers(t)

	body := `{"redirect_uris":["not a valid uri"]}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRegister().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRegister_WrongMethod(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	w := httptest.NewRecorder()
	h.HandleRegister().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleAuthorize_Success(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, _, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state-123"},
		"scope":                 {"openid"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.HandleAuthorize().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}

	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid Location URL: %v", err)
	}

	if !strings.HasPrefix(loc, "https://auth.example.com/realms/test/protocol/openid-connect/auth") {
		t.Errorf("expected redirect to KC auth endpoint, got: %s", loc)
	}
	if locURL.Query().Get("client_id") != "proxy-client" {
		t.Errorf("expected proxy's KC client_id, got: %s", locURL.Query().Get("client_id"))
	}
	if locURL.Query().Get("redirect_uri") != "https://proxy.example.com/oauth/callback" {
		t.Errorf("unexpected redirect_uri: %s", locURL.Query().Get("redirect_uri"))
	}
}

func TestHandleAuthorize_MissingPKCE(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, _, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"state":         {"client-state-123"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.HandleAuthorize().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing PKCE, got %d", w.Code)
	}
}

func TestHandleAuthorize_UnknownClient(t *testing.T) {
	h, _ := newTestHandlers(t)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"nonexistent"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.HandleAuthorize().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown client, got %d", w.Code)
	}
}

func TestHandleAuthorize_UnregisteredRedirectURI(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, _, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://evil.example.com/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.HandleAuthorize().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered redirect_uri, got %d", w.Code)
	}
}

func TestHandleToken_FullFlow(t *testing.T) {
	h, store := newTestHandlers(t)

	// Register client
	clientID, clientSecret, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	// Simulate an auth code with known PKCE challenge
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	ac := &AuthCode{
		Code:                "test-code-123",
		ClientID:            clientID,
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		KCAccessToken:       "kc-access-token",
		KCTokenType:         "Bearer",
		KCExpiresIn:         300,
		KCRefreshToken:      "kc-refresh-token",
		CreatedAt:           time.Now(),
	}
	store.PutAuthCode(ac)

	// Exchange code for tokens
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-code-123"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {verifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["access_token"] != "kc-access-token" {
		t.Errorf("expected kc-access-token, got %v", resp["access_token"])
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected Bearer, got %v", resp["token_type"])
	}
}

func TestHandleToken_InvalidPKCE(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, clientSecret, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	challenge := computeS256Challenge("correct-verifier")
	ac := &AuthCode{
		Code:          "test-code-pkce",
		ClientID:      clientID,
		RedirectURI:   "http://localhost:3000/callback",
		CodeChallenge: challenge,
		KCAccessToken: "kc-token",
		KCTokenType:   "Bearer",
		CreatedAt:     time.Now(),
	}
	store.PutAuthCode(ac)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-code-pkce"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {"wrong-verifier"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid PKCE, got %d", w.Code)
	}
}

func TestHandleToken_CodeReuse(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, clientSecret, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	verifier := "test-verifier"
	challenge := computeS256Challenge(verifier)
	ac := &AuthCode{
		Code:          "test-code-reuse",
		ClientID:      clientID,
		RedirectURI:   "http://localhost:3000/callback",
		CodeChallenge: challenge,
		KCAccessToken: "kc-token",
		KCTokenType:   "Bearer",
		CreatedAt:     time.Now(),
	}
	store.PutAuthCode(ac)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-code-reuse"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {verifier},
	}

	// First exchange should succeed
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Second exchange should fail (code already used)
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("second exchange: expected 400, got %d", w2.Code)
	}
}

func TestHandleToken_InvalidClientCredentials(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, _, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"client_id":     {clientID},
		"client_secret": {"wrong-secret"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {"verifier"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleToken_MissingParams(t *testing.T) {
	h, _ := newTestHandlers(t)

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"some-code"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleToken_WrongMethod(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleCallback_Success(t *testing.T) {
	h, store := newTestHandlers(t)

	// Set up an auth session
	sess := &AuthSession{
		ClientID:            "client-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid",
		State:               "original-client-state",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		KCState:             "kc-state-abc",
		CreatedAt:           time.Now(),
	}
	store.PutAuthSession(sess)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=kc-code-xyz&state=kc-state-abc", nil)
	w := httptest.NewRecorder()
	h.HandleCallback().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid Location: %v", err)
	}

	if !strings.HasPrefix(loc, "http://localhost:3000/callback") {
		t.Errorf("expected redirect to client callback, got: %s", loc)
	}
	if locURL.Query().Get("state") != "original-client-state" {
		t.Errorf("expected original client state, got: %s", locURL.Query().Get("state"))
	}
	if locURL.Query().Get("code") == "" {
		t.Error("expected proxy code in redirect")
	}
}

func TestHandleCallback_UnknownState(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=kc-code&state=unknown-state", nil)
	w := httptest.NewRecorder()
	h.HandleCallback().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown state, got %d", w.Code)
	}
}

func TestHandleCallback_KCError(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?error=access_denied&error_description=User+denied", nil)
	w := httptest.NewRecorder()
	h.HandleCallback().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for KC error, got %d", w.Code)
	}
}

func TestMetadataHandler_ReturnsCorrectJSON(t *testing.T) {
	store := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	t.Cleanup(store.Close)

	kcEndpoints := &KeycloakEndpoints{
		Issuer:                "https://auth.example.com/realms/test",
		AuthorizationEndpoint: "https://auth.example.com/realms/test/protocol/openid-connect/auth",
		TokenEndpoint:         "https://auth.example.com/realms/test/protocol/openid-connect/token",
	}

	h := NewHandlers(store, kcEndpoints, "https://proxy.example.com", "proxy-client", "proxy-secret",
		[]string{"mcp:read", "mcp:write"}, nil,
		[]string{"https://auth.example.com/realms/test"})

	handler := h.HandleResourceMetadata()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var meta protectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if meta.Resource != "https://proxy.example.com" {
		t.Errorf("expected resource https://proxy.example.com, got %s", meta.Resource)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://auth.example.com/realms/test" {
		t.Errorf("unexpected authorization_servers: %v", meta.AuthorizationServers)
	}
	if len(meta.ScopesSupported) != 2 || meta.ScopesSupported[0] != "mcp:read" || meta.ScopesSupported[1] != "mcp:write" {
		t.Errorf("unexpected scopes_supported: %v", meta.ScopesSupported)
	}
	if len(meta.BearerMethodsSupported) != 1 || meta.BearerMethodsSupported[0] != "header" {
		t.Errorf("unexpected bearer_methods_supported: %v", meta.BearerMethodsSupported)
	}
}

func TestHandleToken_RefreshToken(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, clientSecret, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {"kc-refresh-token-abc"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["access_token"] != "kc-refreshed-access-token" {
		t.Errorf("expected kc-refreshed-access-token, got %v", resp["access_token"])
	}
	if resp["refresh_token"] != "kc-new-refresh-token" {
		t.Errorf("expected kc-new-refresh-token, got %v", resp["refresh_token"])
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected Bearer, got %v", resp["token_type"])
	}
}

func TestHandleToken_RefreshToken_InvalidClient(t *testing.T) {
	h, store := newTestHandlers(t)

	_, _, _ = store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"wrong-client"},
		"client_secret": {"wrong-secret"},
		"refresh_token": {"kc-refresh-token-abc"},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleToken_RefreshToken_MissingParams(t *testing.T) {
	h, store := newTestHandlers(t)

	clientID, clientSecret, _ := store.PutClient([]string{"http://localhost:3000/callback"}, "test", []string{"authorization_code"})

	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing refresh_token",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
			},
		},
		{
			name: "missing client_id",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"client_secret": {clientSecret},
				"refresh_token": {"some-token"},
			},
		},
		{
			name: "missing client_secret",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {clientID},
				"refresh_token": {"some-token"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.HandleToken().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestMetadataHandler_EmptyScopes(t *testing.T) {
	store := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	t.Cleanup(store.Close)

	kcEndpoints := &KeycloakEndpoints{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/protocol/openid-connect/auth",
		TokenEndpoint:         "https://auth.example.com/protocol/openid-connect/token",
	}

	h := NewHandlers(store, kcEndpoints, "https://proxy.example.com", "proxy-client", "proxy-secret",
		nil, nil,
		[]string{"https://auth.example.com"})

	handler := h.HandleResourceMetadata()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// scopes_supported should be omitted when empty (omitempty)
	if _, ok := meta["scopes_supported"]; ok {
		t.Error("expected scopes_supported to be omitted when empty")
	}
}
