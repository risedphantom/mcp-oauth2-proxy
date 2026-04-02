# mcp-oauth2-proxy

HTTP reverse proxy for [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) servers that acts as an **OAuth2 Authorization Server facade** with [Keycloak](https://www.keycloak.org/) as the backing identity provider.

The proxy handles the full MCP authorization lifecycle:
- **RFC 9728** Protected Resource Metadata discovery
- **RFC 8414** Authorization Server Metadata
- **RFC 7591** Dynamic Client Registration
- **OAuth2 Authorization Code** flow with **PKCE (S256)**
- OIDC discovery from Keycloak for token/authorization endpoints
- Configurable header mutations on proxied requests
- SSE (Server-Sent Events) streaming passthrough

## How It Works

```
                         ┌──────────────────────────────────┐
                         │        mcp-oauth2-proxy          │
                         │                                  │
MCP Client ──Bearer──►   │  AuthMiddleware (token presence) │
                         │  Header Mutations (add/remove)   │ ──►  Upstream MCP Server
                         │  ReverseProxy (SSE streaming)    │
                         │                                  │
                         │  OAuth2 AS Facade:               │
                         │   /oauth/register                │
                         │   /oauth/authorize  ◄──────────► │ ──►  Keycloak (OIDC)
                         │   /oauth/callback                │
                         │   /oauth/token                   │
                         └──────────────────────────────────┘
```

**OAuth2 Authorization Code flow:**

1. MCP client discovers the proxy via `GET /.well-known/oauth-protected-resource`
2. Client registers dynamically via `POST /oauth/register` (gets `client_id` + `client_secret`)
3. Client starts authorization via `GET /oauth/authorize` with PKCE S256
4. Proxy redirects to Keycloak — user authenticates
5. Keycloak redirects back to `GET /oauth/callback` — proxy exchanges KC code for tokens
6. Proxy redirects client back with a proxy-issued authorization code
7. Client exchanges the code via `POST /oauth/token` (PKCE verified) — receives Keycloak tokens
8. Client uses the access token as `Authorization: Bearer` on subsequent proxy requests

**Proxied requests** pass through AuthMiddleware (Bearer token presence check, no signature validation) and configurable header mutations before reaching the upstream server.

## Quick Start

### Prerequisites

- Go 1.24+
- A Keycloak instance with a configured realm and client

### Build and Run

```sh
# Build
make build

# Run with example config
make serve

# Or run directly
./mcp-oauth2-proxy serve --config config/config.yaml
```

### Docker

```sh
# Build image
make docker-build

# Run
docker run -v $(pwd)/config.yaml:/app/config.yaml mcp-oauth2-proxy:latest
```

## Configuration

Configuration is loaded from YAML, with support for environment variable overrides (prefix `MCP_OAUTH2_PROXY_`).

### Minimal Example

```yaml
upstream:
  url: http://localhost:3000

auth:
  baseUrl: https://mcp-proxy.example.com
  authorizationServers:
    - https://mcp-proxy.example.com
  issuerUrl: https://auth.example.com/realms/myrealm
  clientId: mcp-proxy
  clientSecret: secret
```

### Full Example

```yaml
server:
  listenAddress: ":8080"
  readTimeout: "30s"
  writeTimeout: "0s"       # 0 = no timeout, required for SSE
  idleTimeout: "120s"

upstream:
  url: http://localhost:3000

headers:
  mutations:
    - action: set-x-forwarded
    - action: remove
      name: X-Unwanted-Header
    - action: add
      name: X-Forwarded-By
      value: mcp-oauth2-proxy
    - action: add
      name: X-Original-Host
      valueFrom:
        requestHeader: Host
    - action: add
      name: X-Query-Token
      valueFrom:
        queryParameter: token
    - action: add
      name: X-Auth-Header
      valueFrom:
        authorizationHeader: true

auth:
  baseUrl: https://mcp-proxy.example.com
  authorizationServers:
    - https://mcp-proxy.example.com
  scopesSupported:
    - mcp:read
    - mcp:write
  oidcScopes:
    - openid
    - profile
    - email
    - groups
  issuerUrl: https://auth.example.com/realms/myrealm
  clientId: mcp-proxy
  clientSecret: secret
  clientTtl: "24h"         # TTL for dynamically registered clients
  sessionTtl: "10m"        # TTL for in-progress auth flows
  codeTtl: "5m"            # TTL for authorization codes
```

### Configuration Reference

| Field | Required | Default | Description |
|---|---|---|---|
| `server.listenAddress` | No | `:8080` | HTTP listen address |
| `server.readTimeout` | No | `30s` | HTTP read timeout |
| `server.writeTimeout` | No | `0s` | HTTP write timeout (0 for SSE) |
| `server.idleTimeout` | No | `120s` | HTTP idle timeout |
| `upstream.url` | **Yes** | — | Upstream MCP server URL (absolute) |
| `headers.mutations` | No | `[]` | Ordered list of header mutations |
| `auth.baseUrl` | **Yes** | — | Proxy's public base URL (OAuth2 issuer) |
| `auth.authorizationServers` | No | `[baseUrl]` | List of authorization server URLs (defaults to baseUrl) |
| `auth.issuerUrl` | **Yes** | — | Keycloak realm URL for OIDC discovery |
| `auth.clientId` | **Yes** | — | Keycloak client ID |
| `auth.clientSecret` | **Yes** | — | Keycloak client secret |
| `auth.scopesSupported` | No | `[]` | Scopes advertised in metadata |
| `auth.oidcScopes` | No | `[]` | Scopes to request from Keycloak |
| `auth.clientTtl` | No | `24h` | TTL for dynamically registered clients |
| `auth.sessionTtl` | No | `10m` | TTL for in-progress auth flows |
| `auth.codeTtl` | No | `5m` | TTL for authorization codes |

### Header Mutations

Mutations are applied in order during request rewriting:

| Action | Fields | Description |
|---|---|---|
| `remove` | `name` | Remove header by name |
| `add` | `name`, `value` or `valueFrom` | Set header from static value or dynamic source |
| `set-x-forwarded` | (none) | Add X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host |

`valueFrom` sources (exactly one):
- `requestHeader: <name>` — copy from incoming request header
- `queryParameter: <name>` — extract from URL query parameter
- `authorizationHeader: true` — extract Bearer token value

### Environment Variables

All config fields can be overridden via environment variables with prefix `MCP_OAUTH2_PROXY_`. Dots are replaced with `_`; camelCase field names are matched case-insensitively:

```sh
export MCP_OAUTH2_PROXY_UPSTREAM_URL=http://localhost:3000
export MCP_OAUTH2_PROXY_AUTH_ISSUERURL=https://auth.example.com/realms/myrealm
export MCP_OAUTH2_PROXY_AUTH_CLIENTID=mcp-proxy
export MCP_OAUTH2_PROXY_AUTH_CLIENTSECRET=secret
```

## API Endpoints

### Health & Readiness

```sh
curl http://localhost:8080/healthz   # → "ok"
curl http://localhost:8080/readyz    # → "ok"
```

### OAuth2 Discovery

```sh
# RFC 9728 Protected Resource Metadata
curl http://localhost:8080/.well-known/oauth-protected-resource

# RFC 8414 Authorization Server Metadata
curl http://localhost:8080/.well-known/oauth-authorization-server
```

### Dynamic Client Registration (RFC 7591)

```sh
curl -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "my-mcp-client",
    "grant_types": ["authorization_code"]
  }'
```

### Authorization & Token Exchange

```sh
# Start authorization (browser redirect)
GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...&scope=...

# Exchange code for tokens
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=...&client_id=...&client_secret=...&redirect_uri=...&code_verifier=..."
```

## Kubernetes Deployment

A Helm chart is provided in `deploy/helm/`.

```sh
# Install
helm install mcp-oauth2-proxy deploy/helm \
  -n mcp-oauth2-proxy --create-namespace \
  -f values-production.yaml

# Debug template rendering
make helm-debug
```

The chart includes:
- **Deployment** with liveness (`/healthz`) and readiness (`/readyz`) probes
- **Service** (ClusterIP, port 8080)
- **ConfigMap** for proxy configuration (mounted at `/app/config.yaml`)
- **ServiceAccount** with auto-mount
- Security context: `readOnlyRootFilesystem`, `runAsNonRoot`, drop ALL capabilities

## Development

```sh
make build           # Build binary
make test            # Run tests
make test-coverage   # Tests with coverage report
make lint            # Run golangci-lint
make fmt             # Format code
make deps            # Download and tidy dependencies
```

### CLI Flags

```
mcp-oauth2-proxy serve --config <path>     # Config file path (default: config.yaml)
mcp-oauth2-proxy serve --log-level DEBUG   # Log level: DEBUG, INFO, WARN, ERROR, FATAL, PANIC
mcp-oauth2-proxy serve --log-format json   # Log format: text, json
mcp-oauth2-proxy version                   # Print version info
```

## CI/CD

GitLab CI pipeline (`.gitlab-ci.yml`):
- **Docker image**: built and pushed on semver tags (e.g., `1.0.0`)
- **Helm chart**: packaged and pushed on `helm-*` tags (e.g., `helm-1.0.0`)
- Includes shared CI templates for multi-arch builds, security scanning, and Helm publishing
