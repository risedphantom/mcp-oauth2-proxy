package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
)

// Handlers implements the OAuth2 Authorization Server facade endpoints.
type Handlers struct {
	store           *Store
	kcEndpoints     *KeycloakEndpoints
	proxyBaseURL    string
	kcClientID      string
	kcClientSecret  string
	scopesSupported []string
	oidcScopes      []string
	httpClient      *http.Client

	// Pre-serialized AS metadata JSON.
	asMetadataJSON []byte
	// Pre-serialized RFC 9728 Protected Resource Metadata JSON.
	resourceMetadataJSON []byte
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	store *Store,
	kcEndpoints *KeycloakEndpoints,
	proxyBaseURL string,
	kcClientID string,
	kcClientSecret string,
	scopesSupported []string,
	oidcScopes []string,
	authorizationServers []string,
) *Handlers {
	h := &Handlers{
		store:           store,
		kcEndpoints:     kcEndpoints,
		proxyBaseURL:    strings.TrimRight(proxyBaseURL, "/"),
		kcClientID:      kcClientID,
		kcClientSecret:  kcClientSecret,
		scopesSupported: scopesSupported,
		oidcScopes:      oidcScopes,
		httpClient:      &http.Client{Timeout: 15 * time.Second},
	}
	h.asMetadataJSON = h.buildASMetadata()
	h.resourceMetadataJSON = h.buildResourceMetadata(authorizationServers)
	return h
}

// authorizationServerMetadata represents the RFC 8414 Authorization Server Metadata document.
type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}

func (h *Handlers) buildASMetadata() []byte {
	meta := authorizationServerMetadata{
		Issuer:                            h.proxyBaseURL,
		AuthorizationEndpoint:             h.proxyBaseURL + "/oauth/authorize",
		TokenEndpoint:                     h.proxyBaseURL + "/oauth/token",
		RegistrationEndpoint:              h.proxyBaseURL + "/oauth/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{grantTypeAuthorizationCode, grantTypeRefreshToken},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   h.scopesSupported,
	}
	data, _ := json.Marshal(meta) //nolint:errcheck // static struct, cannot fail
	return data
}

// HandleASMetadata serves the RFC 8414 Authorization Server Metadata document.
func (h *Handlers) HandleASMetadata() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(h.asMetadataJSON) //nolint:errcheck
	})
}

// registerRequest is the expected JSON body for POST /oauth/register.
type registerRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
}

// HandleRegister handles dynamic client registration (RFC 7591).
func (h *Handlers) HandleRegister() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body")
			return
		}

		var req registerRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
			return
		}
		for _, uri := range req.RedirectURIs {
			if _, err := url.ParseRequestURI(uri); err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
					fmt.Sprintf("invalid redirect_uri: %s", uri))
				return
			}
		}

		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{grantTypeAuthorizationCode}
		}

		clientID, clientSecret, err := h.store.PutClient(req.RedirectURIs, req.ClientName, grantTypes)
		if err != nil {
			log.WithError(err).Error("Failed to create client")
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to create client")
			return
		}

		resp := map[string]any{
			"client_id":                  clientID,
			"client_secret":              clientSecret,
			"client_id_issued_at":        time.Now().Unix(),
			"redirect_uris":              req.RedirectURIs,
			"client_name":                req.ClientName,
			"grant_types":                grantTypes,
			"token_endpoint_auth_method": "client_secret_post",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})
}

// HandleAuthorize handles the authorization endpoint (GET /oauth/authorize).
// It validates the request and redirects the browser to Keycloak's authorization endpoint.
func (h *Handlers) HandleAuthorize() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
			return
		}

		q := r.URL.Query()

		responseType := q.Get("response_type")
		if responseType != "code" {
			writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "Only response_type=code is supported")
			return
		}

		clientID := q.Get("client_id")
		if h.store.GetClient(clientID) == nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Unknown client_id")
			return
		}

		redirectURI := q.Get("redirect_uri")
		if redirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
			return
		}
		if !h.store.HasRedirectURI(clientID, redirectURI) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered")
			return
		}

		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge with method S256 is required")
			return
		}

		clientState := q.Get("state")
		scope := q.Get("scope")

		kcState, err := GenerateState()
		if err != nil {
			log.WithError(err).Error("Failed to generate KC state")
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Internal error")
			return
		}

		session := &AuthSession{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			State:               clientState,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			KCState:             kcState,
			CreatedAt:           time.Now(),
		}
		h.store.PutAuthSession(session)

		// Build Keycloak authorization URL
		kcURL, _ := url.Parse(h.kcEndpoints.AuthorizationEndpoint) //nolint:errcheck
		kcQuery := kcURL.Query()
		kcQuery.Set("response_type", "code")
		kcQuery.Set("client_id", h.kcClientID)
		kcQuery.Set("redirect_uri", h.proxyBaseURL+"/oauth/callback")
		kcQuery.Set("state", kcState)
		if len(h.oidcScopes) > 0 {
			kcQuery.Set("scope", strings.Join(h.oidcScopes, " "))
		} else if scope != "" {
			kcQuery.Set("scope", scope)
		}
		kcURL.RawQuery = kcQuery.Encode()

		http.Redirect(w, r, kcURL.String(), http.StatusFound)
	})
}

// HandleCallback handles the Keycloak callback (GET /oauth/callback).
// It exchanges the KC authorization code for tokens and redirects back to the MCP client.
func (h *Handlers) HandleCallback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Check for KC error response
		if kcErr := q.Get("error"); kcErr != "" {
			log.WithFields(log.Fields{
				"error":             kcErr,
				"error_description": q.Get("error_description"),
			}).Error("Keycloak returned error in callback")
			writeOAuthError(w, http.StatusBadGateway, "server_error", "Authorization server returned an error")
			return
		}

		kcCode := q.Get("code")
		kcState := q.Get("state")
		if kcCode == "" || kcState == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing code or state")
			return
		}

		session := h.store.PopAuthSession(kcState)
		if session == nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Unknown or expired session")
			return
		}

		// Exchange KC code for KC tokens
		kcTokens, err := h.exchangeKCCode(r.Context(), kcCode)
		if err != nil {
			log.WithError(err).Error("Failed to exchange KC code for tokens")
			writeOAuthError(w, http.StatusBadGateway, "server_error", "Failed to exchange authorization code")
			return
		}

		// Generate proxy authorization code
		proxyCode, err := GenerateCode()
		if err != nil {
			log.WithError(err).Error("Failed to generate proxy code")
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Internal error")
			return
		}

		authCode := &AuthCode{
			Code:                proxyCode,
			ClientID:            session.ClientID,
			RedirectURI:         session.RedirectURI,
			Scope:               session.Scope,
			CodeChallenge:       session.CodeChallenge,
			CodeChallengeMethod: session.CodeChallengeMethod,
			KCAccessToken:       kcTokens.AccessToken,
			KCRefreshToken:      kcTokens.RefreshToken,
			KCIDToken:           kcTokens.IDToken,
			KCExpiresIn:         kcTokens.ExpiresIn,
			KCTokenType:         kcTokens.TokenType,
			CreatedAt:           time.Now(),
		}
		h.store.PutAuthCode(authCode)

		// Redirect back to the MCP client's redirect_uri
		clientRedirect, _ := url.Parse(session.RedirectURI) //nolint:errcheck
		cq := clientRedirect.Query()
		cq.Set("code", proxyCode)
		if session.State != "" {
			cq.Set("state", session.State)
		}
		clientRedirect.RawQuery = cq.Encode()

		http.Redirect(w, r, clientRedirect.String(), http.StatusFound)
	})
}

// kcTokenResponse represents the token response from Keycloak.
type kcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func (h *Handlers) exchangeKCCode(ctx context.Context, code string) (*kcTokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantTypeAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {h.proxyBaseURL + "/oauth/callback"},
		"client_id":     {h.kcClientID},
		"client_secret": {h.kcClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.kcEndpoints.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating KC token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting KC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading KC token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KC token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp kcTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding KC token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("KC token response missing access_token")
	}

	return &tokenResp, nil
}

// HandleToken handles the token endpoint (POST /oauth/token).
// It verifies PKCE, validates client credentials, and returns the Keycloak tokens.
func (h *Handlers) HandleToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
			return
		}

		grantType := r.PostFormValue("grant_type")

		switch grantType {
		case grantTypeAuthorizationCode:
			h.handleAuthorizationCodeGrant(w, r)
		case grantTypeRefreshToken:
			h.handleRefreshTokenGrant(w, r)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
		}
	})
}

func (h *Handlers) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")
	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")

	if code == "" || clientID == "" || clientSecret == "" || redirectURI == "" || codeVerifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	if !h.store.ValidateClientCredentials(clientID, clientSecret) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	ac := h.store.ConsumeAuthCode(code)
	if ac == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or already used authorization code")
		return
	}

	if ac.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	if ac.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	if !VerifyPKCES256(codeVerifier, ac.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	resp := map[string]any{
		"access_token": ac.KCAccessToken,
		"token_type":   ac.KCTokenType,
	}
	if ac.KCExpiresIn > 0 {
		resp["expires_in"] = ac.KCExpiresIn
	}
	if ac.KCRefreshToken != "" {
		resp["refresh_token"] = ac.KCRefreshToken
	}
	if ac.KCIDToken != "" {
		resp["id_token"] = ac.KCIDToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (h *Handlers) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")
	refreshToken := r.PostFormValue("refresh_token")

	if clientID == "" || clientSecret == "" || refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	if !h.store.ValidateClientCredentials(clientID, clientSecret) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	kcTokens, err := h.refreshKCToken(r.Context(), refreshToken)
	if err != nil {
		log.WithError(err).Error("Failed to refresh KC token")
		writeOAuthError(w, http.StatusBadGateway, "server_error", "Failed to refresh token")
		return
	}

	resp := map[string]any{
		"access_token": kcTokens.AccessToken,
		"token_type":   kcTokens.TokenType,
	}
	if kcTokens.ExpiresIn > 0 {
		resp["expires_in"] = kcTokens.ExpiresIn
	}
	if kcTokens.RefreshToken != "" {
		resp["refresh_token"] = kcTokens.RefreshToken
	}
	if kcTokens.IDToken != "" {
		resp["id_token"] = kcTokens.IDToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (h *Handlers) refreshKCToken(ctx context.Context, refreshToken string) (*kcTokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantTypeRefreshToken},
		"refresh_token": {refreshToken},
		"client_id":     {h.kcClientID},
		"client_secret": {h.kcClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.kcEndpoints.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating KC refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting KC token refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading KC refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KC token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp kcTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding KC refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("KC refresh response missing access_token")
	}

	return &tokenResp, nil
}

// writeOAuthError writes an RFC 6749 error response.
func writeOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             errorCode,
		"error_description": description,
	})
}

// protectedResourceMetadata represents the RFC 9728 Protected Resource Metadata document.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (h *Handlers) buildResourceMetadata(authorizationServers []string) []byte {
	meta := protectedResourceMetadata{
		Resource:               h.proxyBaseURL,
		AuthorizationServers:   authorizationServers,
		ScopesSupported:        h.scopesSupported,
		BearerMethodsSupported: []string{"header"},
	}
	data, _ := json.Marshal(meta) //nolint:errcheck // static struct, cannot fail
	return data
}

// HandleResourceMetadata serves the RFC 9728 Protected Resource Metadata document
// at /.well-known/oauth-protected-resource.
func (h *Handlers) HandleResourceMetadata() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(h.resourceMetadataJSON) //nolint:errcheck
	})
}
