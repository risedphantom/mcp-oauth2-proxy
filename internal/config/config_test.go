package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testProxyURL = "https://mcp-proxy.example.com"

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const authYAML = `
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`

const baseYAML = `
upstream:
  url: "http://localhost:3000"
` + authYAML

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
server:
  listenAddress: ":9090"
  readTimeout: "10s"
  writeTimeout: "0s"
  idleTimeout: "60s"
upstream:
  url: "http://localhost:3000"
headers:
  mutations:
    - action: remove
      name: "X-Remove"
    - action: add
      name: "X-Custom"
      value: "value"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test-client"
  clientSecret: "test-secret"
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.ListenAddress != ":9090" {
		t.Errorf("expected listenAddress :9090, got %s", cfg.Server.ListenAddress)
	}
	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("expected readTimeout 10s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 0 {
		t.Errorf("expected writeTimeout 0, got %v", cfg.Server.WriteTimeout)
	}
	if cfg.Upstream.URL != "http://localhost:3000" {
		t.Errorf("expected upstream url http://localhost:3000, got %s", cfg.Upstream.URL)
	}
	if cfg.Auth.ClientID != "test-client" {
		t.Errorf("expected clientId test-client, got %s", cfg.Auth.ClientID)
	}
	if len(cfg.Headers.Mutations) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(cfg.Headers.Mutations))
	}
	if cfg.Headers.Mutations[0].Action != MutationActionRemove || cfg.Headers.Mutations[0].Name != "X-Remove" {
		t.Errorf("unexpected mutation[0]: %+v", cfg.Headers.Mutations[0])
	}
	if cfg.Headers.Mutations[1].Action != MutationActionAdd || cfg.Headers.Mutations[1].Name != "X-Custom" || cfg.Headers.Mutations[1].Value != "value" {
		t.Errorf("unexpected mutation[1]: %+v", cfg.Headers.Mutations[1])
	}
}

func TestLoad_MissingUpstreamURL(t *testing.T) {
	yaml := `
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing upstream.url")
	}
}

func TestLoad_MissingIssuerURL(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing auth.issuerUrl")
	}
}

func TestLoad_MissingClientID(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing clientId")
	}
}

func TestLoad_MissingClientSecret(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing clientSecret")
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, baseYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.ListenAddress != ":8080" {
		t.Errorf("expected default listenAddress :8080, got %s", cfg.Server.ListenAddress)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected default readTimeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if len(cfg.Headers.Mutations) != 0 {
		t.Errorf("expected no default mutations, got %d", len(cfg.Headers.Mutations))
	}
}

func TestValidateHeaders_InvalidAction(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: "bogus"
      name: "X-Foo"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for invalid action")
	}
}

func TestValidateHeaders_RemoveWithoutName(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: remove
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for remove without name")
	}
}

func TestValidateHeaders_RemoveWithValue(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: remove
      name: "X-Foo"
      value: "bar"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for remove with value")
	}
}

func TestValidateHeaders_AddWithoutName(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      value: "bar"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for add without name")
	}
}

func TestValidateHeaders_AddWithNeitherValueNorValueFrom(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Foo"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for add with neither value nor valueFrom")
	}
}

func TestValidateHeaders_AddWithBothValueAndValueFrom(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Foo"
      value: "bar"
      valueFrom:
        requestHeader: "Host"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for add with both value and valueFrom")
	}
}

func TestValidateHeaders_ValueFromMultipleSources(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Foo"
      valueFrom:
        requestHeader: "Host"
        queryParameter: "token"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for valueFrom with multiple sources")
	}
}

func TestValidateHeaders_ValueFromNoSources(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Foo"
      valueFrom: {}
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for valueFrom with no sources")
	}
}

func TestValidateHeaders_EmptyMutationsValid(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations: []
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHeaders_ValueFromRequestHeader(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Original-Host"
      valueFrom:
        requestHeader: "Host"
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Headers.Mutations) != 1 {
		t.Fatalf("expected 1 mutation, got %d", len(cfg.Headers.Mutations))
	}
	m := cfg.Headers.Mutations[0]
	if m.ValueFrom == nil || m.ValueFrom.RequestHeader != "Host" {
		t.Errorf("unexpected valueFrom: %+v", m.ValueFrom)
	}
}

func TestValidateHeaders_ValueFromQueryParameter(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: add
      name: "X-Token"
      valueFrom:
        queryParameter: "token"
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Headers.Mutations) != 1 {
		t.Fatalf("expected 1 mutation, got %d", len(cfg.Headers.Mutations))
	}
	m := cfg.Headers.Mutations[0]
	if m.ValueFrom == nil || m.ValueFrom.QueryParameter != "token" {
		t.Errorf("unexpected valueFrom: %+v", m.ValueFrom)
	}
}

// --- set-x-forwarded validation tests ---

func TestValidateHeaders_SetXForwardedValid(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: set-x-forwarded
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHeaders_SetXForwardedWithName(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: set-x-forwarded
      name: "X-Foo"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for set-x-forwarded with name")
	}
}

func TestValidateHeaders_SetXForwardedWithValue(t *testing.T) {
	yaml := baseYAML + `
headers:
  mutations:
    - action: set-x-forwarded
      value: "bar"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for set-x-forwarded with value")
	}
}

// --- Auth config validation tests ---

func TestAuthConfig_ValidFull(t *testing.T) {
	cfg, err := Load(writeConfig(t, baseYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.BaseURL != testProxyURL {
		t.Errorf("expected baseUrl %s, got %s", testProxyURL, cfg.Auth.BaseURL)
	}
}

func TestAuthConfig_MissingBaseURL(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing auth.baseUrl")
	}
}

func TestAuthConfig_MissingAuthSection(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing auth section")
	}
}

func TestAuthConfig_MissingAuthorizationServers_DefaultsToBaseURL(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	cfg, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Auth.AuthorizationServers) != 1 {
		t.Fatalf("expected 1 authorization server, got %d", len(cfg.Auth.AuthorizationServers))
	}
	if cfg.Auth.AuthorizationServers[0] != "https://mcp-proxy.example.com" {
		t.Fatalf("expected authorizationServers to default to baseUrl, got %q", cfg.Auth.AuthorizationServers[0])
	}
}

func TestAuthConfig_BaseURLNotAbsolute(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "not-a-url"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for non-absolute baseUrl")
	}
}

func TestAuthConfig_BaseURLWithFragment(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com#frag"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for baseUrl with fragment")
	}
}

func TestLoad_UpstreamURLNotAbsolute(t *testing.T) {
	yaml := `
upstream:
  url: "not-a-url"
` + authYAML
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for non-absolute upstream.url")
	}
}

func TestLoad_AuthorizationServerNotAbsolute(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "not-a-url"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for non-absolute authorizationServers entry")
	}
}

func TestLoad_AuthorizationServerValid(t *testing.T) {
	yaml := `
upstream:
  url: "http://localhost:3000"
auth:
  baseUrl: "https://mcp-proxy.example.com"
  authorizationServers:
    - "https://auth.example.com"
  issuerUrl: "https://auth.example.com"
  clientId: "test"
  clientSecret: "secret"
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Auth TTL default tests ---

func TestAuthConfig_TTLDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, baseYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.BaseURL != testProxyURL {
		t.Errorf("expected baseUrl %s, got %s", testProxyURL, cfg.Auth.BaseURL)
	}
	if cfg.Auth.ClientTTL != 24*time.Hour {
		t.Errorf("expected default clientTtl 24h, got %v", cfg.Auth.ClientTTL)
	}
	if cfg.Auth.SessionTTL != 10*time.Minute {
		t.Errorf("expected default sessionTtl 10m, got %v", cfg.Auth.SessionTTL)
	}
	if cfg.Auth.CodeTTL != 5*time.Minute {
		t.Errorf("expected default codeTtl 5m, got %v", cfg.Auth.CodeTTL)
	}
}
