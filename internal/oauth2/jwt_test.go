package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTestJWKSServer creates an httptest server serving a JWKS document with the given RSA public key.
func newTestJWKSServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	body, _ := json.Marshal(jwks)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func signToken(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func newValidator(t *testing.T, srv *httptest.Server) *JWTValidator {
	t.Helper()
	v, err := NewJWTValidator(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	return v
}

func TestJWTValidator_ValidToken(t *testing.T) {
	key := generateRSAKey(t)
	srv := newTestJWKSServer(t, &key.PublicKey)
	defer srv.Close()

	v := newValidator(t, srv)
	tokenStr := signToken(t, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "user1",
	}, key)

	if err := v.Validate(tokenStr); err != nil {
		t.Errorf("expected valid token, got error: %v", err)
	}
}

func TestJWTValidator_ExpiredToken(t *testing.T) {
	key := generateRSAKey(t)
	srv := newTestJWKSServer(t, &key.PublicKey)
	defer srv.Close()

	v := newValidator(t, srv)
	tokenStr := signToken(t, jwt.MapClaims{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"sub": "user1",
	}, key)

	if err := v.Validate(tokenStr); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestJWTValidator_MissingExp(t *testing.T) {
	key := generateRSAKey(t)
	srv := newTestJWKSServer(t, &key.PublicKey)
	defer srv.Close()

	v := newValidator(t, srv)
	tokenStr := signToken(t, jwt.MapClaims{
		"sub": "user1",
	}, key)

	if err := v.Validate(tokenStr); err == nil {
		t.Error("expected error for missing exp claim")
	}
}

func TestJWTValidator_WrongSigningKey(t *testing.T) {
	serverKey := generateRSAKey(t)
	signingKey := generateRSAKey(t)
	srv := newTestJWKSServer(t, &serverKey.PublicKey)
	defer srv.Close()

	v := newValidator(t, srv)
	tokenStr := signToken(t, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "user1",
	}, signingKey)

	if err := v.Validate(tokenStr); err == nil {
		t.Error("expected error for wrong signing key")
	}
}

func TestJWTValidator_NilValidator(t *testing.T) {
	var v *JWTValidator
	if err := v.Validate("any-token"); err != nil {
		t.Errorf("nil validator should pass, got error: %v", err)
	}
}

func TestJWTValidator_MalformedToken(t *testing.T) {
	key := generateRSAKey(t)
	srv := newTestJWKSServer(t, &key.PublicKey)
	defer srv.Close()

	v := newValidator(t, srv)
	if err := v.Validate("not-a-jwt"); err == nil {
		t.Error("expected error for malformed token")
	}
}
