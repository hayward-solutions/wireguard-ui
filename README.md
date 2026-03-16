# WireGuard UI

A self-hosted WireGuard VPN management interface with a clean web UI, REST API, and support for both kernel and userspace WireGuard modes.

## Features

- **One-click peer management** — create peers, download configs, scan QR codes
- **Userspace WireGuard** — runs without a kernel module (Docker, ECS Fargate, etc.)
- **OIDC authentication** — integrate with any OpenID Connect provider, or use local username/password
- **Role-based access** — admins see all peers; regular users see only their own
- **REST API** — full CRUD with API key support for automation
- **Real-time stats** — live connection status, handshake times, and transfer data via SSE
- **Single binary** — Go backend with embedded SvelteKit SPA, no external dependencies
- **Multi-database** — SQLite (default) or PostgreSQL
- **Encrypted key storage** — peer private keys encrypted at rest with AES-256-GCM

## Quick Start

```bash
docker compose up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in with `admin` / `changeme`.

For production, create a `.env` file:

```env
ADMIN_PASSWORD=your-secure-password
JWT_SECRET=your-random-secret
WG_ENDPOINT=vpn.example.com:51820
```

## Configuration

All configuration is via environment variables.

### Required

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret for signing JWT tokens | — |
| `WG_ENDPOINT` | Public hostname or host:port for client configs | — |
| `ADMIN_PASSWORD` | Local admin password (required if OIDC not configured) | — |

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

### Other

| Variable | Description | Default |
|----------|-------------|---------|
| `ENCRYPTION_KEY` | Key for at-rest encryption (defaults to JWT_SECRET) | — |
| `JWT_EXPIRY` | JWT token lifetime | `24h` |
| `STATS_INTERVAL` | How often to poll WireGuard stats | `10s` |

## Docker Compose

```yaml
services:
  wireguard-ui:
    image: ghcr.io/hayward-solutions/wireguard-ui:latest
    ports:
      - "8080:8080"
      - "51820:51820/udp"
    environment:
      - ADMIN_PASSWORD=changeme
      - JWT_SECRET=changeme
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

### Peers

```
GET    /api/v1/peers              # List peers (filtered by ownership)
POST   /api/v1/peers              # Create peer
GET    /api/v1/peers/:id          # Get peer
PUT    /api/v1/peers/:id          # Update peer
DELETE /api/v1/peers/:id          # Delete peer
PATCH  /api/v1/peers/:id/toggle   # Enable/disable peer
GET    /api/v1/peers/:id/config   # Download .conf file
GET    /api/v1/peers/:id/qrcode   # Get QR code (PNG)
```

### Server (admin only for writes)

```
GET    /api/v1/server             # Get server config
PUT    /api/v1/server             # Update server config
POST   /api/v1/server/apply       # Apply config to WireGuard interface
```

### Auth

```
GET    /auth/login                # OIDC login redirect
GET    /auth/callback             # OIDC callback
POST   /auth/logout               # Clear session
GET    /auth/me                   # Current user info
POST   /auth/local                # Local username/password login
```

### Stats

```
GET    /api/v1/stats              # Current peer stats
GET    /api/v1/stats/stream       # SSE real-time stats stream
```

### Users (admin only)

```
GET    /api/v1/users              # List users
POST   /api/v1/users              # Create user
GET    /api/v1/users/:id          # Get user
PUT    /api/v1/users/:id          # Update user
DELETE /api/v1/users/:id          # Delete user
POST   /api/v1/me/password        # Change own password
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
  auth/                     # OIDC, JWT, middleware
  database/                 # Store interface, SQLite + PostgreSQL implementations
  domain/                   # Models (Peer, ServerConfig, User)
  wireguard/                # Manager interface, wgctrl, userspace, mock, IP allocation
  api/                      # HTTP handlers, routing, authorization
  monitor/                  # Background stats polling
  crypto/                   # AES-256-GCM encryption for key storage
frontend/                   # SvelteKit SPA (Tailwind CSS, Svelte 5)
```

### Key design decisions

- **Userspace-first** — `WG_USERSPACE_MODE=true` by default for container compatibility
- **Single binary** — the built SPA is embedded via `go:embed`
- **Pure Go SQLite** — uses `modernc.org/sqlite`, no CGo required (`CGO_ENABLED=0`)
- **Auto NAT/masquerade** — default PostUp/PostDown iptables rules are generated on first boot
- **Peer re-sync** — all enabled peers are re-applied to the WireGuard interface on every startup

## License

MIT
