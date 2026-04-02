# AGENTS.md — mcp-oauth2-proxy

## What This Project Is

HTTP reverse proxy for MCP (Model Context Protocol) servers that acts as an **OAuth2 Authorization Server facade**. It handles dynamic client registration, authorization code flow with PKCE, and proxies requests to upstream MCP servers with header mutations. Keycloak is the backing identity provider via OIDC discovery.

## Architecture Overview

```
MCP Client ──► mcp-oauth2-proxy ──► Upstream MCP Server
                    │
                    ├─ OAuth2 AS facade (register, authorize, callback, token)
                    ├─ RFC 9728 / RFC 8414 metadata endpoints
                    ├─ Auth middleware (Bearer token presence, no validation)
                    ├─ Header mutations (add/remove/set-x-forwarded/valueFrom)
                    ├─ OIDC discovery → Keycloak (authorization + token endpoints)
                    └─ SSE streaming passthrough (FlushInterval: -1, WriteTimeout: 0)
```

**Two request flows:**
1. **OAuth2 flow** — Client registers → authorizes → proxy redirects to Keycloak → callback exchanges code → client gets tokens
2. **Proxy flow** — Client sends Bearer token → AuthMiddleware checks presence → header mutations applied → forwarded to upstream

## Project Layout

```
cmd/main.go                      Cobra CLI: serve, version commands
internal/
  config/config.go               YAML config via viper, validation, defaults
  middleware/
    auth.go                      Bearer token presence check, WWW-Authenticate challenges
    logging.go                   Request/response logging, body capture, skip paths
  oauth2/
    discovery.go                 OIDC .well-known/openid-configuration fetch
    handlers.go                  OAuth2 AS endpoints (register, authorize, callback, token, metadata)
    store.go                     In-memory store: clients, sessions, codes (thread-safe, TTL, cleanup)
    pkce.go                      PKCE S256 verification (SHA256 + base64url + constant-time compare)
  proxy/proxy.go                 httputil.ReverseProxy with Rewrite, header mutations, SSE
  server/server.go               HTTP server setup, route registration, graceful shutdown
utils/
  errors/errors.go               DieOnError, LogOnError helpers
  httplog/httplog.go             JSON body capture (64KB limit), header map conversion
  log/log.go                     Logrus init (level, format, context logger)
config/
  config.example.yaml            Full example configuration
  config.local.yaml              Local dev config (Keycloak at risedphantom.tech)
deploy/helm/                     Helm chart (Deployment, Service, ConfigMap, ServiceAccount)
```

## Conventions & Stack

- **Go 1.24**, module `github.com/risedphantom/mcp-oauth2-proxy`
- **stdlib only** for HTTP: `net/http` + `httputil.ReverseProxy` (no Gin/Echo — transparent streaming proxy)
- **Config**: YAML via viper, env vars prefix `MCP_OAUTH2_PROXY_`, CLI flags via cobra
- **Logging**: logrus, JSON format by default
- **Tests**: stdlib `testing` + `httptest`, no external test frameworks (testify, gomock, etc.)
- **Linter**: golangci-lint (`.golangci.yml`), includes revive, staticcheck, dupl, gocyclo, etc.
- **Docker**: multi-stage build, `distroless/static:nonroot` runtime, CGO_ENABLED=0
- **CI**: GitLab CI — semver tags trigger Docker build, `helm-*` tags trigger Helm publish

## Key Design Decisions

| Decision | Rationale |
|---|---|
| `FlushInterval: -1`, `WriteTimeout: 0` | SSE streaming — flush every write, no timeout on long-lived connections |
| `Rewrite` (not `Director`) | Modern httputil API with `SetURL` + `SetXForwarded` |
| Auth middleware: presence only, no validation | Proxy checks token exists but never verifies signatures (no JWKS) |
| Middleware ordering: Auth → Proxy(HeaderMutator) | Client token checked before header mutations replace it |
| In-memory OAuth2 store with background cleanup | No external DB dependency; 60s cleanup interval; single-use codes/sessions |
| PKCE S256 required | All authorization requests must include code_challenge with S256 method |
| Client secrets hashed with SHA256 | Stored as `[32]byte`, validated with `subtle.ConstantTimeCompare` |
| Static config, restart to reload | Matches K8s ConfigMap convention |
| OIDC discovery once at startup | Token/authorization endpoints cached for process lifetime |

## HTTP Routes

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/healthz` | No | Inline — returns "ok" |
| GET | `/readyz` | No | Inline — returns "ok" |
| GET | `/.well-known/oauth-protected-resource` | No | RFC 9728 metadata (pre-serialized JSON) |
| GET | `/.well-known/oauth-authorization-server` | No | RFC 8414 metadata (pre-serialized JSON) |
| POST | `/oauth/register` | No | RFC 7591 dynamic client registration |
| GET | `/oauth/authorize` | No | Validates params, redirects to Keycloak |
| GET | `/oauth/callback` | No | Exchanges KC code, redirects to client with proxy code |
| POST | `/oauth/token` | No | Validates PKCE + client creds, returns KC tokens |
| `*` | `/` (catch-all) | **Yes** | AuthMiddleware → ReverseProxy |

## Header Mutations

Applied in order inside `proxy.Rewrite()`:

| Action | Description |
|---|---|
| `remove` | Deletes header by name |
| `add` | Sets header from static `value` or dynamic `valueFrom` |
| `set-x-forwarded` | Calls `SetXForwarded()` (X-Forwarded-For/Proto/Host) |

`valueFrom` sources (exactly one required):
- `requestHeader` — copy from incoming request header
- `queryParameter` — extract from URL query parameter
- `authorizationHeader` — extract Bearer token value

## Build Commands

```sh
make build           # Build binary with LDFLAGS (version, commit, time)
make test            # go test -v ./...
make lint            # golangci-lint run
make fmt             # go fmt + gofmt -s
make serve           # Build + run with config/config.example.yaml
make docker-build    # Multi-stage Docker build
make helm-debug      # Render Helm templates to deploy/helm/helm-debug.yaml
make test-coverage   # Tests + coverage.html
make deps            # go mod download + tidy
```

## Configuration

Required fields:
- `upstream.url` — upstream MCP server (absolute URL)
- `auth.baseUrl` — proxy's public URL (used as OAuth2 issuer and resource identifier)
- `auth.issuerUrl` — Keycloak realm URL for OIDC discovery
- `auth.clientId` — Keycloak client ID
- `auth.clientSecret` — Keycloak client secret

Optional (with defaults):

- `auth.authorizationServers` — list of AS URLs (defaults to `[baseUrl]`)

Defaults: listen `:8080`, read timeout 30s, write timeout 0 (SSE), idle timeout 120s, client TTL 24h, session TTL 10m, code TTL 5m.

## Modifying the Codebase

- All OAuth2/OIDC logic is in `internal/oauth2/` — handlers, store, discovery, PKCE
- Proxy behavior (header mutations, upstream rewriting) is in `internal/proxy/proxy.go`
- Auth middleware is separate from proxy — `internal/middleware/auth.go`
- Config structs and validation are in `internal/config/config.go` — add new fields there with viper defaults in `setDefaults()`
- The `challengeWriter` in auth middleware implements `http.Flusher` and `Unwrap()` — preserve this for SSE and `http.ResponseController` compatibility
- The logging `responseWriter` wrapper also implements `Flusher` and `Unwrap()` — same requirement
- Tests use no external frameworks — keep using stdlib `testing` + `httptest`
