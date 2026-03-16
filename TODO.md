# WireGuard UI — TODO

## Core Infrastructure

- [ ] Implement real wgctrl Manager (replace MockManager with actual WireGuard interface management)
- [ ] Integrate wireguard-go as library for userspace networking (ECS Fargate support)
- [ ] PostgreSQL Store implementation with connection pooling
- [ ] Encrypt peer private keys at rest (AES-GCM via `ENCRYPTION_KEY`)
- [ ] Database migration versioning (track applied migrations, support incremental upgrades)

## Auth & Security

- [ ] CSRF protection on state-changing endpoints
- [ ] Rate limiting on login and API endpoints
- [ ] Role-based access control enforcement (admin/editor/viewer permissions per endpoint)
- [ ] API key scoping (read-only vs read-write keys)
- [ ] Support multiple local user accounts (not just a single admin)
- [ ] Password hashing for local users stored in DB (bcrypt/argon2)
- [ ] Session revocation / token blacklist

## API

- [ ] Tunnel CRUD endpoints (site-to-site, point-to-site)
- [ ] Pagination on list endpoints (`?page=1&limit=20`)
- [ ] Filtering on peer list (`?enabled=true`, `?search=name`)
- [ ] Bulk operations (enable/disable/delete multiple peers)
- [ ] OpenAPI / Swagger spec generation
- [ ] Webhook support (notify external systems on peer create/delete)

## Frontend

- [ ] Redirect to dashboard after successful login
- [ ] Tunnel management page
- [ ] Peer detail page (`/peers/[id]`) with edit form and stats history
- [ ] Real-time transfer rate charts (not just cumulative totals)
- [ ] Dark mode toggle
- [ ] Mobile responsive sidebar (collapse to hamburger)
- [ ] Toast notifications for success/error actions
- [ ] Confirmation dialogs with peer name for destructive actions
- [ ] User management page (admin only)
- [ ] Settings page (change password, generate API keys)

## DevOps & Operations

- [ ] CI/CD pipeline (GitHub Actions: lint, test, build, push image)
- [ ] Container image publishing to GHCR/ECR
- [ ] ECS Fargate task definition and Terraform/CDK example
- [ ] Health check endpoint improvements (include DB connectivity, WG interface status)
- [ ] Structured logging improvements (request tracing, log levels)
- [ ] Graceful peer re-sync on startup (reconcile DB state with WG interface)
- [ ] Backup/restore for SQLite database

## Testing

- [ ] Unit tests for database Store (SQLite, in-memory)
- [ ] Unit tests for JWT issuance/validation
- [ ] Unit tests for IP allocation logic
- [ ] Unit tests for config rendering
- [ ] API handler tests with httptest
- [ ] Integration tests with real SQLite database
- [ ] E2E tests with Playwright against Docker stack
- [ ] OIDC flow testing with local Keycloak in docker-compose

## Documentation

- [ ] README with setup instructions, screenshots, and architecture overview
- [ ] Environment variable reference table
- [ ] API documentation with curl examples
- [ ] Contributing guide
