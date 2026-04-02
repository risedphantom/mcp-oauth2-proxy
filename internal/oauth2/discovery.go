package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// KeycloakEndpoints holds the discovered Keycloak OIDC endpoints.
type KeycloakEndpoints struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JwksURI               string
}

// DiscoverKeycloak fetches the OpenID Connect discovery document from the given issuer URL
// and extracts the authorization and token endpoints.
func DiscoverKeycloak(ctx context.Context, issuerURL string) (*KeycloakEndpoints, error) {
	return discoverKeycloak(ctx, issuerURL, &http.Client{Timeout: 10 * time.Second})
}

func discoverKeycloak(ctx context.Context, issuerURL string, client *http.Client) (*KeycloakEndpoints, error) {
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	log.WithField("url", discoveryURL).Info("Fetching Keycloak discovery document for OAuth2 AS facade")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating KC discovery request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching KC discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KC discovery endpoint returned status %d", resp.StatusCode)
	}

	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding KC discovery document: %w", err)
	}

	if doc.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("KC discovery document missing authorization_endpoint")
	}
	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("KC discovery document missing token_endpoint")
	}

	if doc.JwksURI == "" {
		return nil, fmt.Errorf("KC discovery document missing jwks_uri")
	}

	log.WithFields(log.Fields{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JwksURI,
	}).Info("Discovered Keycloak endpoints")

	return &KeycloakEndpoints{
		Issuer:                doc.Issuer,
		AuthorizationEndpoint: doc.AuthorizationEndpoint,
		TokenEndpoint:         doc.TokenEndpoint,
		JwksURI:               doc.JwksURI,
	}, nil
}
