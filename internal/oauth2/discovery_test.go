package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverKeycloak_Success(t *testing.T) {
	doc := map[string]string{
		"issuer":                 "https://auth.example.com/realms/test",
		"authorization_endpoint": "https://auth.example.com/realms/test/protocol/openid-connect/auth",
		"token_endpoint":         "https://auth.example.com/realms/test/protocol/openid-connect/token",
		"jwks_uri":               "https://auth.example.com/realms/test/protocol/openid-connect/certs",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	defer srv.Close()

	endpoints, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if endpoints.AuthorizationEndpoint != doc["authorization_endpoint"] {
		t.Errorf("expected %s, got %s", doc["authorization_endpoint"], endpoints.AuthorizationEndpoint)
	}
	if endpoints.TokenEndpoint != doc["token_endpoint"] {
		t.Errorf("expected %s, got %s", doc["token_endpoint"], endpoints.TokenEndpoint)
	}
	if endpoints.Issuer != doc["issuer"] {
		t.Errorf("expected %s, got %s", doc["issuer"], endpoints.Issuer)
	}
	if endpoints.JwksURI != doc["jwks_uri"] {
		t.Errorf("expected %s, got %s", doc["jwks_uri"], endpoints.JwksURI)
	}
}

func TestDiscoverKeycloak_MissingJwksURI(t *testing.T) {
	doc := map[string]string{
		"issuer":                 "https://auth.example.com/realms/test",
		"authorization_endpoint": "https://auth.example.com/realms/test/protocol/openid-connect/auth",
		"token_endpoint":         "https://auth.example.com/realms/test/protocol/openid-connect/token",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	defer srv.Close()

	_, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for missing jwks_uri")
	}
}

func TestDiscoverKeycloak_MissingAuthorizationEndpoint(t *testing.T) {
	doc := map[string]string{
		"issuer":         "https://auth.example.com/realms/test",
		"token_endpoint": "https://auth.example.com/realms/test/protocol/openid-connect/token",
		"jwks_uri":       "https://auth.example.com/realms/test/protocol/openid-connect/certs",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	defer srv.Close()

	_, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for missing authorization_endpoint")
	}
}

func TestDiscoverKeycloak_MissingTokenEndpoint(t *testing.T) {
	doc := map[string]string{
		"issuer":                 "https://auth.example.com/realms/test",
		"authorization_endpoint": "https://auth.example.com/realms/test/protocol/openid-connect/auth",
		"jwks_uri":               "https://auth.example.com/realms/test/protocol/openid-connect/certs",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	defer srv.Close()

	_, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for missing token_endpoint")
	}
}

func TestDiscoverKeycloak_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}

func TestDiscoverKeycloak_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := discoverKeycloak(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
