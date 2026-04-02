package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
	oauth2facade "github.com/risedphantom/mcp-oauth2-proxy/internal/oauth2"
	log "github.com/sirupsen/logrus"
)

// AuthMiddleware checks for the presence and validity of a Bearer JWT token before
// forwarding to the next handler. It verifies the token signature and expiration,
// and returns RFC-compliant WWW-Authenticate challenges on failure.
type AuthMiddleware struct {
	next                http.Handler
	validator           *oauth2facade.JWTValidator
	resourceMetadataURL string
	scopesSupported     string
}

// NewAuthMiddleware creates an AuthMiddleware wrapping the given handler.
// If validator is nil, only token presence is checked (no signature/expiration validation).
func NewAuthMiddleware(next http.Handler, cfg config.AuthConfig, validator *oauth2facade.JWTValidator) *AuthMiddleware {
	return &AuthMiddleware{
		next:                next,
		validator:           validator,
		resourceMetadataURL: cfg.BaseURL + "/.well-known/oauth-protected-resource",
		scopesSupported:     strings.Join(cfg.ScopesSupported, " "),
	}
}

// ServeHTTP checks for a Bearer token, validates its signature and expiration,
// and returns a WWW-Authenticate challenge if absent or invalid.
func (m *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenString := ExtractBearerToken(r)
	if tokenString == "" {
		m.writeChallenge(w, http.StatusUnauthorized, "")
		return
	}

	if err := m.validator.Validate(tokenString); err != nil {
		log.WithError(err).Warn("JWT validation failed")
		m.writeChallenge(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	cw := &challengeWriter{ResponseWriter: w, middleware: m}
	m.next.ServeHTTP(cw, r)
}

// challengeWriter intercepts upstream 401/403 responses and rewrites them
// with RFC-compliant WWW-Authenticate challenges.
type challengeWriter struct {
	http.ResponseWriter
	middleware  *AuthMiddleware
	intercepted bool
}

func (cw *challengeWriter) WriteHeader(code int) {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		cw.intercepted = true
		errorCode := "invalid_token"
		if code == http.StatusForbidden {
			errorCode = "insufficient_scope"
		}
		cw.middleware.writeChallenge(cw.ResponseWriter, code, errorCode)
		return
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *challengeWriter) Write(b []byte) (int, error) {
	if cw.intercepted {
		return len(b), nil
	}
	return cw.ResponseWriter.Write(b)
}

func (cw *challengeWriter) Flush() {
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (cw *challengeWriter) Unwrap() http.ResponseWriter {
	return cw.ResponseWriter
}

// writeChallenge writes a WWW-Authenticate response for missing or invalid tokens.
func (m *AuthMiddleware) writeChallenge(w http.ResponseWriter, status int, errorCode string) {
	var challenge string
	if errorCode == "" {
		// No token provided — include scope hint for discovery.
		challenge = fmt.Sprintf(`Bearer resource_metadata="%s"`, m.resourceMetadataURL)
		if m.scopesSupported != "" {
			challenge += fmt.Sprintf(`, scope="%s"`, m.scopesSupported)
		}
	} else {
		challenge = fmt.Sprintf(`Bearer error="%s", resource_metadata="%s"`, errorCode, m.resourceMetadataURL)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(status)
}

// ExtractBearerToken extracts the token from the Authorization: Bearer <token> header.
func ExtractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
