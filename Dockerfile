# Stage 1: Build frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build backend
FROM golang:1.25-alpine AS backend-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/frontend/build ./frontend/build
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /wireguard-ui ./cmd/server

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates iptables ip6tables wireguard-tools
COPY --from=backend-builder /wireguard-ui /usr/local/bin/wireguard-ui
RUN mkdir -p /data
EXPOSE 8080 51820/udp
ENTRYPOINT ["wireguard-ui"]
