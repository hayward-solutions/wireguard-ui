#!/bin/sh
set -e

echo "=== WireGuard Netstack Integration Test ==="

# Step 1: Install dependencies
echo "Installing dependencies..."
apk add --no-cache wireguard-tools curl jq > /dev/null

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

# Step 8: Show tunnel stats
echo ""
echo "=== Tunnel Stats ==="
wg show

echo ""
echo "=== ALL TESTS PASSED ==="
exit 0
