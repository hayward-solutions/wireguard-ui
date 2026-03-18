.PHONY: dev dev-backend dev-frontend build test test-vpn test-tunnel lint docker clean

# Run both frontend and backend with hot reload
dev:
	$(MAKE) -j2 dev-backend dev-frontend

dev-backend:
	WG_MOCK_MODE=true WG_ENDPOINT=localhost:51820 \
	  go run -ldflags="-X github.com/hayward-solutions/wireguard-ui/internal/config.devBuild=true" ./cmd/server

dev-frontend:
	cd frontend && npm run dev -- --port 5173

# Build production binary
build: build-frontend build-backend

build-frontend:
	cd frontend && npm ci && npm run build

build-backend:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/wireguard-ui ./cmd/server

# Run tests
test:
	go test ./...

test-frontend:
	cd frontend && npm test

# Integration test: verify WireGuard netstack tunnel works without NET_ADMIN
test-vpn:
	docker compose -f tests/integration/docker-compose.test.yml build
	docker compose -f tests/integration/docker-compose.test.yml up --abort-on-container-exit --exit-code-from wg-client; \
	  EXIT_CODE=$$?; \
	  docker compose -f tests/integration/docker-compose.test.yml down -v; \
	  exit $$EXIT_CODE

# Integration test: verify WireGuard tunnel routing between two servers
test-tunnel:
	docker compose -f tests/integration/tunnel/docker-compose.test.yml build
	docker compose -f tests/integration/tunnel/docker-compose.test.yml up --abort-on-container-exit --exit-code-from test-runner; \
	  EXIT_CODE=$$?; \
	  docker compose -f tests/integration/tunnel/docker-compose.test.yml down -v; \
	  exit $$EXIT_CODE

# Lint
lint:
	golangci-lint run ./...

lint-frontend:
	cd frontend && npm run lint

# Docker
docker:
	docker build -t wireguard-ui .

# Clean
clean:
	rm -rf bin/ frontend/build/ frontend/.svelte-kit/
