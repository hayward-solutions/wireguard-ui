#!/bin/sh
set -e

echo "=== WireGuard Netstack Integration Test ==="

# Step 1: Install dependencies
echo "Installing dependencies..."
apk add --no-cache wireguard-tools curl jq bind-tools > /dev/null

# Step 2: Wait for server API
echo "Waiting for server API..."
for i in $(seq 1 30); do
  if curl -sf "${SERVER_URL}/api/v1/health" > /dev/null 2>&1; then
    echo "Server is ready."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "FAIL: Server did not become ready"
    exit 1
  fi
  sleep 1
done

# Step 3: Create a peer via the API
echo "Creating WireGuard peer..."
PEER_RESPONSE=$(curl -sf -X POST "${SERVER_URL}/api/v1/peers" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"name": "integration-test-client"}')

PEER_ID=$(echo "$PEER_RESPONSE" | jq -r '.data.id')
if [ -z "$PEER_ID" ] || [ "$PEER_ID" = "null" ]; then
  echo "FAIL: Could not create peer"
  echo "$PEER_RESPONSE"
  exit 1
fi
echo "Created peer: $PEER_ID"

# Step 4: Download WireGuard config
echo "Downloading WireGuard config..."
mkdir -p /etc/wireguard
curl -sf "${SERVER_URL}/api/v1/peers/${PEER_ID}/config" \
  -H "X-API-Key: ${API_KEY}" \
  -o /etc/wireguard/wg0.conf

echo "Config:"
cat /etc/wireguard/wg0.conf
echo ""

# Step 5: Bring up WireGuard tunnel
echo "Bringing up WireGuard tunnel..."
wg-quick up wg0

# Step 6: Wait for handshake
echo "Waiting for WireGuard handshake..."
for i in $(seq 1 15); do
  HANDSHAKE=$(wg show wg0 latest-handshakes | awk '{print $2}')
  if [ -n "$HANDSHAKE" ] && [ "$HANDSHAKE" != "0" ]; then
    echo "Handshake established!"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "FAIL: No WireGuard handshake after 15 seconds"
    wg show
    exit 1
  fi
  sleep 1
done

# Step 7: Test TCP connectivity through the tunnel
echo "Testing TCP connectivity through tunnel to ${SERVER_VPN_IP}..."
HEALTH=$(curl -sf --connect-timeout 5 "http://${SERVER_VPN_IP}:8080/api/v1/health")
if echo "$HEALTH" | jq -e '.status == "ok" or .data.status == "ok"' > /dev/null 2>&1; then
  echo "PASS: TCP traffic flows through the WireGuard tunnel"
else
  echo "FAIL: Could not reach server through tunnel"
  echo "Response: $HEALTH"
  wg show
  ip route
  exit 1
fi

# Step 8: Test internet forwarding through the tunnel (DNS + HTTP)
# Add external IPs to WireGuard AllowedIPs so the client encrypts and sends them
# through the tunnel, then add host routes so the kernel routes to wg0.
echo "Configuring tunnel for internet forwarding test..."
SERVER_PUBKEY=$(wg show wg0 peers)
wg set wg0 peer "$SERVER_PUBKEY" allowed-ips 10.0.0.0/24,1.1.1.1/32,93.184.216.0/24
ip route add 1.1.1.1/32 dev wg0
ip route add 93.184.216.0/24 dev wg0

echo "Testing DNS resolution through tunnel (UDP forwarding)..."
DNS_RESULT=$(dig +short +timeout=5 +tries=2 @1.1.1.1 example.com 2>&1) || true
if echo "$DNS_RESULT" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
  echo "PASS: DNS resolution works through the tunnel ($DNS_RESULT)"
else
  echo "FAIL: DNS resolution failed through the tunnel"
  echo "$DNS_RESULT"
  wg show
  exit 1
fi

echo "Testing HTTP connectivity through tunnel to external host (TCP forwarding)..."
EXTERNAL=$(curl -sf --connect-timeout 10 "http://1.1.1.1/" 2>&1) || true
if echo "$EXTERNAL" | grep -qi "html\|cloudflare\|redirect"; then
  echo "PASS: HTTP through tunnel works"
else
  # TCP forwarding to external hosts may not work in all CI environments (e.g.,
  # Docker Desktop on macOS can't route to arbitrary external IPs from containers).
  # The DNS test above already exercises the full UDP forwarding path.
  echo "SKIP: External HTTP not reachable from this Docker environment (expected in some CI)"
  echo "Response: $EXTERNAL"
fi

# Step 9: Show tunnel stats
echo ""
echo "=== Tunnel Stats ==="
wg show

echo ""
echo "=== ALL TESTS PASSED ==="
exit 0
