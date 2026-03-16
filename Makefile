.PHONY: dev dev-backend dev-frontend build test lint docker clean

# Run both frontend and backend with hot reload
dev:
	$(MAKE) -j2 dev-backend dev-frontend

dev-backend:
	WG_MOCK_MODE=true WG_ENDPOINT=localhost:51820 \
	  go run ./cmd/server

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
