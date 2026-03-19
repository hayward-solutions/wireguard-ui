# WireGuard UI

A self-hosted WireGuard VPN management interface with a clean web UI, REST API, and support for both kernel and userspace WireGuard modes.

## Features

- **One-click peer management** — create peers, download configs, scan QR codes
- **Client-side key generation** — keys generated in the browser so the server never sees peer private keys; server-side generation available as a fallback
- **Userspace WireGuard** — runs without a kernel module (Docker, Kubernetes, etc.)
- **gVisor netstack** — fully userspace networking for ECS Fargate and serverless (no `NET_ADMIN` required)
- **OIDC authentication** — integrate with any OpenID Connect provider, or use local username/password
- **Role-based access** — three roles: admin (full control), editor (manage own peers), viewer (read-only)
- **Groups & ACL network policies** — fine-grained L3/L4 network access rules per user or group
- **Peer isolation by default** — peer-to-peer traffic is denied unless explicitly allowed
- **REST API** — full CRUD with JWT and API key support for automation
- **API token self-service** — users can generate their own read-only API tokens
- **Real-time stats** — live connection status, handshake times, and transfer data via SSE
- **Single binary** — Go backend with embedded SvelteKit SPA, no external dependencies
- **Multi-database** — SQLite (default) or PostgreSQL
- **Encrypted key storage** — server-generated peer private keys encrypted at rest with AES-256-GCM; client-generated keys are never stored on the server
- **Rate limiting & account lockout** — brute-force protection on auth endpoints
- **Audit logging** — structured JSON logs of auth events and sensitive operations
- **HTTPS enforcement** — optional automatic HTTPS redirect

## Quick Start

Create a `.env` file with the required secrets (see `.env.example`):

```env
ADMIN_PASSWORD=your-secure-password
JWT_SECRET=your-random-jwt-secret    # min 16 characters
ENCRYPTION_KEY=your-encryption-key   # min 16 characters, must differ from JWT_SECRET
WG_ENDPOINT=vpn.example.com:51820
```

Then start the stack:

```bash
docker compose up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in with the `admin` username and the password you configured.

> **Note:** The app rejects well-known weak values (e.g. `changeme`, `password`, `secret`) and enforces minimum lengths for cryptographic secrets. It will refuse to start if secrets are missing or weak.

### Serverless / Fargate Deployment

For environments without `NET_ADMIN` or `/dev/net/tun` (e.g., ECS Fargate), use the netstack profile:

```bash
docker compose --profile fargate up -d
```

This runs WireGuard entirely in userspace via gVisor netstack — no kernel module, no capabilities, no TUN device.

## Configuration

All configuration is via environment variables.

### Required

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret for signing JWT tokens (min 16 chars) | — |
| `ENCRYPTION_KEY` | Key for at-rest encryption of peer private keys (min 16 chars, must differ from `JWT_SECRET`) | — |
| `WG_ENDPOINT` | Public hostname or host:port for client configs | — |
| `ADMIN_PASSWORD` | Local admin password (required if OIDC not configured) | — |

> Weak or well-known values (e.g. `changeme`, `password`, `secret`) are rejected at startup.

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | HTTP listen address | `:8080` |
| `BASE_URL` | Public URL of the web UI | `http://localhost:8080` |

### Database

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_DRIVER` | `sqlite` or `postgres` | `sqlite` |
| `DATABASE_DSN` | Database connection string | `/data/wireguard.db` |

### WireGuard

| Variable | Description | Default |
|----------|-------------|---------|
| `WG_ADDRESS` | Server VPN address (CIDR) | `10.0.0.1/24` |
| `WG_LISTEN_PORT` | WireGuard UDP listen port | `51820` |
| `WG_DNS` | DNS servers for peers | `1.1.1.1,8.8.8.8` |
| `WG_DEFAULT_ALLOWED_IPS` | Default allowed IPs for new peers | `0.0.0.0/0, ::/0` |
| `WG_INTERFACE_NAME` | WireGuard interface name | `wg0` |
| `WG_MTU` | Interface MTU | `1420` |
| `WG_USERSPACE_MODE` | Use wireguard-go instead of kernel module | `true` |
| `WG_NETSTACK_MODE` | Use gVisor netstack (fully userspace, no NET_ADMIN) | `false` |
| `WG_MOCK_MODE` | Mock WireGuard for development | `false` |

### Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_USERNAME` | Local admin username | `admin` |
| `ADMIN_API_KEY` | API key for programmatic access (admin role) | — |
| `OIDC_ISSUER_URL` | OIDC provider issuer URL | — |
| `OIDC_CLIENT_ID` | OIDC client ID | — |
| `OIDC_CLIENT_SECRET` | OIDC client secret | — |
| `OIDC_REDIRECT_URL` | OIDC callback URL | `{BASE_URL}/auth/callback` |
| `OIDC_SCOPES` | OIDC scopes to request | `openid,profile,email` |
| `OIDC_ADMIN_GROUP` | OIDC group claim whose members are granted admin role | — |
| `OIDC_GROUPS_CLAIM` | OIDC token claim used to extract group memberships | `cognito:groups` |

#### Authentication Policies

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOW_PASSWORDLESS_LOGIN` | Allow users to sign in with WebAuthn/passkey without a password | `true` |
| `MFA_REQUIRED` | Require multi-factor authentication for all users | `false` |

### Tunnels

| Variable | Description | Default |
|----------|-------------|---------|
| `TUNNEL_PEERS` | JSON array of tunnel peer configurations for first-boot provisioning | — |
| `TUNNEL_SUBNET` | CIDR range used to auto-allocate /30 addresses for inter-server tunnels | `10.100.0.0/16` |

<details>
<summary>Example TUNNEL_PEERS JSON</summary>

```json
[
  {
    "public_key": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+Ab=",
    "endpoint": "peer1.example.com:51820",
    "allowed_ips": ["10.100.0.0/30"]
  },
  {
    "public_key": "zYxWvUtSrQpOnMlKjIhGfEdCbA9876543210/Zy=",
    "endpoint": "peer2.example.com:51820",
    "allowed_ips": ["10.100.0.4/30"]
  }
]
```

</details>

### Security

| Variable | Description | Default |
|----------|-------------|---------|
| `REQUIRE_HTTPS` | Enforce HTTPS redirect on all requests | `false` |
| `CORS_ORIGINS` | Comma-separated allowed origins for CORS | — |
| `TRUSTED_PROXIES` | Comma-separated trusted proxy IPs for forwarded headers | — |
| `ALLOW_CUSTOM_SCRIPTS` | Allow raw PostUp/PostDown shell scripts in server config | `false` |

### Other

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_EXPIRY` | JWT token lifetime | `15m` |
| `SESSION_EXPIRY` | Browser session lifetime | `168h` |
| `STATS_INTERVAL` | How often to poll WireGuard stats | `10s` |
| `API_TOKEN_MAX_LIFETIME` | Maximum lifetime for user-generated API tokens | `2160h` (90 days) |
| `DEV_MODE` | Enable development features | `false` |

## Docker Compose

```yaml
services:
  wireguard-ui:
    image: ghcr.io/hayward-solutions/wireguard-ui:latest
    ports:
      - "8080:8080"
      - "51820:51820/udp"
    environment:
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - WG_ENDPOINT=vpn.example.com:51820
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
    volumes:
      - wireguard-data:/data
    devices:
      - /dev/net/tun:/dev/net/tun
    restart: unless-stopped

volumes:
  wireguard-data:
```

## API

All endpoints return `{ "data": ..., "error": ... }`. Authenticate with a JWT cookie or `Authorization: Bearer <api-key>` header.

### Auth (unauthenticated, rate-limited)

```
GET    /auth/info                       # Available auth methods
GET    /auth/login                      # OIDC login redirect or login page
POST   /auth/login                      # Local username/password login
GET    /auth/callback                   # OIDC callback
POST   /auth/logout                     # Clear session
POST   /auth/refresh                    # Refresh JWT token
GET    /auth/me                         # Current user info (authenticated)
```

### Peers (ownership-enforced, editor+ for writes)

```
GET    /api/v1/peers                    # List peers (filtered by ownership)
POST   /api/v1/peers                    # Create peer
GET    /api/v1/peers/{id}               # Get peer
PUT    /api/v1/peers/{id}               # Update peer
DELETE /api/v1/peers/{id}               # Delete peer
PATCH  /api/v1/peers/{id}/toggle        # Enable/disable peer
GET    /api/v1/peers/{id}/config        # Download .conf file
GET    /api/v1/peers/{id}/qrcode        # Get QR code (PNG)
```

### Server (admin only for writes)

```
GET    /api/v1/server                   # Get server config
PUT    /api/v1/server                   # Update server config
POST   /api/v1/server/apply             # Apply config to WireGuard interface
```

### Stats

```
GET    /api/v1/stats                    # Current peer stats
GET    /api/v1/stats/stream             # SSE real-time stats stream
```

### Users (admin only)

```
GET    /api/v1/users                    # List users
POST   /api/v1/users                    # Create user
GET    /api/v1/users/{id}               # Get user
PUT    /api/v1/users/{id}               # Update user
DELETE /api/v1/users/{id}               # Delete user
POST   /api/v1/users/{id}/reset-password # Admin password reset
GET    /api/v1/users/{id}/groups        # Get user's groups
PUT    /api/v1/users/{id}/groups        # Set user's groups
```

### Self-service

```
POST   /api/v1/me/password              # Change own password
GET    /api/v1/me/tokens                # List own API tokens
POST   /api/v1/me/tokens                # Create API token
DELETE /api/v1/me/tokens/{id}           # Revoke API token
```

### Groups (admin only)

```
GET    /api/v1/groups                   # List groups
POST   /api/v1/groups                   # Create group
GET    /api/v1/groups/{id}              # Get group
PUT    /api/v1/groups/{id}              # Update group
DELETE /api/v1/groups/{id}              # Delete group
GET    /api/v1/groups/{id}/members      # List group members
```

### ACL Rules (admin only)

```
GET    /api/v1/acls                     # List all ACL rules
POST   /api/v1/acls                     # Create rule
GET    /api/v1/acls/{id}                # Get rule
PUT    /api/v1/acls/{id}                # Update rule
DELETE /api/v1/acls/{id}                # Delete rule
POST   /api/v1/acls/reload              # Reload policy engine
GET    /api/v1/acls/effective/{userID}  # Get effective rules for user
```

### Health

```
GET    /api/v1/health                   # Returns {"status": "ok"}
```

### Example: Create a peer via API

```bash
curl -X POST http://localhost:8080/api/v1/peers \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-laptop"}'
```

## Development

### Prerequisites

- Go 1.25+
- Node.js 22+
- npm

### Run locally

```bash
# Start backend (mock WireGuard) + frontend dev server with hot reload
make dev
```

The backend runs on `:8080` and proxies to the Vite dev server on `:5173` in dev mode.

### Build

```bash
# Production binary with embedded SPA
make build

# Docker image
make docker
```

### Test

```bash
make test            # Go tests
make test-frontend   # Frontend tests
make lint            # Go linting
make lint-frontend   # Frontend linting
```

## Architecture

```
cmd/server/main.go          # Entrypoint, DI, graceful shutdown
internal/
  config/                   # Environment variable parsing
  auth/                     # OIDC, JWT, local auth, rate limiting, middleware
  database/                 # Store interface, SQLite + PostgreSQL implementations
  domain/                   # Models (Peer, ServerConfig, User, Group, ACLRule, APIToken, Session)
  wireguard/                # Manager interface: wgctrl, userspace, netstack, mock, IP allocation
  api/                      # HTTP handlers, routing, RBAC authorization
  acl/                      # In-memory ACL policy engine for network-level access control
  monitor/                  # Background stats polling
  crypto/                   # AES-256-GCM encryption for key storage
frontend/                   # SvelteKit SPA (Tailwind CSS, Svelte 5)
```

### Key design decisions

- **Userspace-first** — `WG_USERSPACE_MODE=true` by default for container compatibility
- **Netstack option** — `WG_NETSTACK_MODE=true` for fully userspace networking (Fargate, serverless)
- **Single binary** — the built SPA is embedded via `go:embed`
- **Pure Go SQLite** — uses `modernc.org/sqlite`, no CGo required (`CGO_ENABLED=0`)
- **Structured firewall config** — declarative NAT/masquerade settings replace raw shell scripts by default; `ALLOW_CUSTOM_SCRIPTS=true` re-enables PostUp/PostDown
- **Peer isolation** — peer-to-peer (wg→wg) traffic is dropped by default; configurable via `AllowPeerToPeer` in the server firewall settings
- **Client-side key generation** — the browser generates WireGuard keys using X25519 so the server never handles peer private keys; preshared keys are disclosed once at creation time
- **Peer re-sync** — all enabled peers are re-applied to the WireGuard interface on every startup

## License

MIT
