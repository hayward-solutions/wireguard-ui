#!/bin/sh
set -e

echo "=== WireGuard Tunnel Integration Test ==="
echo ""
echo "Architecture:"
echo "  Client --> [Server A 10.0.0.0/24] --tunnel--> [Server B 10.1.0.0/24]"
echo ""

# Step 1: Install dependencies
echo "[1/8] Installing dependencies..."
apk add --no-cache wireguard-tools curl jq > /dev/null

# Step 2: Wait for both servers
echo "[2/8] Waiting for servers..."
for SERVER_URL in "$SERVER_A_URL" "$SERVER_B_URL"; do
  for i in $(seq 1 30); do
    if curl -sf "${SERVER_URL}/api/v1/health" > /dev/null 2>&1; then
      echo "  $(echo $SERVER_URL | sed 's|http://||;s|:.*||') is ready"
      break
    fi
    if [ "$i" -eq 30 ]; then
      echo "FAIL: Server $SERVER_URL did not become ready"
      exit 1
    fi
    sleep 1
  done
done

# Step 3: Create a tunnel on Server A pointing to Server B
echo "[3/8] Creating tunnel on Server A -> Server B..."
TUNNEL_A_RESPONSE=$(curl -sf -X POST "${SERVER_A_URL}/api/v1/tunnels" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d '{
    "name": "tunnel-to-b",
    "description": "Tunnel from A to B",
    "address": "10.100.0.1/30",
    "listen_port": 51825,
    "peer_allowed_ips": "10.1.0.0/24"
  }')

TUNNEL_A_ID=$(echo "$TUNNEL_A_RESPONSE" | jq -r '.data.id')
TUNNEL_A_PUBKEY=$(echo "$TUNNEL_A_RESPONSE" | jq -r '.data.public_key')
TUNNEL_A_PSK=$(echo "$TUNNEL_A_RESPONSE" | jq -r '.data.preshared_key // empty')

if [ -z "$TUNNEL_A_ID" ] || [ "$TUNNEL_A_ID" = "null" ]; then
  echo "FAIL: Could not create tunnel on Server A"
  echo "$TUNNEL_A_RESPONSE" | jq .
  exit 1
fi
echo "  Tunnel A created: id=$TUNNEL_A_ID"
echo "  Public key: $TUNNEL_A_PUBKEY"

# Step 4: Create a tunnel on Server B pointing to Server A
echo "[4/8] Creating tunnel on Server B -> Server A..."
TUNNEL_B_RESPONSE=$(curl -sf -X POST "${SERVER_B_URL}/api/v1/tunnels" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_B_API_KEY}" \
  -d "{
    \"name\": \"tunnel-to-a\",
    \"description\": \"Tunnel from B to A\",
    \"address\": \"10.100.0.2/30\",
    \"listen_port\": 51826,
    \"peer_public_key\": \"${TUNNEL_A_PUBKEY}\",
    \"peer_endpoint\": \"server-a:51825\",
    \"peer_allowed_ips\": \"10.0.0.0/24\"
  }")

TUNNEL_B_ID=$(echo "$TUNNEL_B_RESPONSE" | jq -r '.data.id')
TUNNEL_B_PUBKEY=$(echo "$TUNNEL_B_RESPONSE" | jq -r '.data.public_key')

if [ -z "$TUNNEL_B_ID" ] || [ "$TUNNEL_B_ID" = "null" ]; then
  echo "FAIL: Could not create tunnel on Server B"
  echo "$TUNNEL_B_RESPONSE" | jq .
  exit 1
fi
echo "  Tunnel B created: id=$TUNNEL_B_ID"
echo "  Public key: $TUNNEL_B_PUBKEY"

# Step 5: Update Tunnel A with Server B's public key and endpoint
echo "[5/8] Updating tunnel A with Server B's public key..."
UPDATE_RESPONSE=$(curl -sf -X PUT "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d "{
    \"peer_public_key\": \"${TUNNEL_B_PUBKEY}\",
    \"peer_endpoint\": \"server-b:51826\"
  }")

if echo "$UPDATE_RESPONSE" | jq -e '.data.peer_public_key' > /dev/null 2>&1; then
  echo "  Tunnel A updated with B's public key"
else
  echo "FAIL: Could not update tunnel A"
  echo "$UPDATE_RESPONSE" | jq .
  exit 1
fi

# Step 6: Wait for tunnel handshake
echo "[6/8] Waiting for tunnel handshake between servers..."
TUNNEL_CONNECTED=false
for i in $(seq 1 20); do
  STATUS_A=$(curl -sf "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/status" \
    -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null || echo '{}')
  CONNECTED=$(echo "$STATUS_A" | jq -r '.data.connected // false')
  if [ "$CONNECTED" = "true" ]; then
    echo "  Tunnel handshake established!"
    TUNNEL_CONNECTED=true
    break
  fi
  sleep 1
done

if [ "$TUNNEL_CONNECTED" = "false" ]; then
  echo "WARN: Tunnel handshake not confirmed via status API (may still work)"
  echo "  Status A: $STATUS_A"
fi

# Step 7: Create a client peer on Server A and connect
echo "[7/8] Connecting client to Server A..."
PEER_RESPONSE=$(curl -sf -X POST "${SERVER_A_URL}/api/v1/peers" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d '{"name": "tunnel-test-client"}')

PEER_ID=$(echo "$PEER_RESPONSE" | jq -r '.data.id')
if [ -z "$PEER_ID" ] || [ "$PEER_ID" = "null" ]; then
  echo "FAIL: Could not create peer on Server A"
  echo "$PEER_RESPONSE" | jq .
  exit 1
fi
echo "  Client peer created: $PEER_ID"

# Download config and connect
mkdir -p /etc/wireguard
curl -sf "${SERVER_A_URL}/api/v1/peers/${PEER_ID}/config" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -o /etc/wireguard/wg0.conf

echo "  Client config:"
cat /etc/wireguard/wg0.conf
echo ""

wg-quick up wg0

# Wait for client handshake
echo "  Waiting for client handshake..."
for i in $(seq 1 15); do
  HANDSHAKE=$(wg show wg0 latest-handshakes | awk '{print $2}')
  if [ -n "$HANDSHAKE" ] && [ "$HANDSHAKE" != "0" ]; then
    echo "  Client handshake established!"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "FAIL: No client WireGuard handshake after 15 seconds"
    wg show
    exit 1
  fi
  sleep 1
done

# Step 8: Test connectivity
echo "[8/8] Testing connectivity..."

# Test 1: Client -> Server A (direct, through VPN)
echo "  Test 1: Client -> Server A (${SERVER_A_VPN_IP})..."
HEALTH_A=$(curl -sf --connect-timeout 5 "http://${SERVER_A_VPN_IP}:8080/api/v1/health" 2>&1 || true)
if echo "$HEALTH_A" | jq -e '.status == "ok" or .data.status == "ok"' > /dev/null 2>&1; then
  echo "  PASS: Client can reach Server A through VPN"
else
  echo "  FAIL: Client cannot reach Server A through VPN"
  echo "  Response: $HEALTH_A"
  wg show
  exit 1
fi

# Test 2: Client -> Server B (through tunnel)
# The client needs a route to 10.1.0.0/24 via the WireGuard interface.
# Add the tunnel subnet to the client's AllowedIPs.
echo "  Test 2: Client -> Server B subnet (${SERVER_B_VPN_IP}) through tunnel..."
SERVER_PUBKEY=$(wg show wg0 peers)
wg set wg0 peer "$SERVER_PUBKEY" allowed-ips 10.0.0.0/24,10.1.0.0/24
ip route add 10.1.0.0/24 dev wg0 2>/dev/null || true

HEALTH_B=$(curl -sf --connect-timeout 10 "http://${SERVER_B_VPN_IP}:8080/api/v1/health" 2>&1 || true)
if echo "$HEALTH_B" | jq -e '.status == "ok" or .data.status == "ok"' > /dev/null 2>&1; then
  echo "  PASS: Client can reach Server B through the tunnel!"
else
  echo "  FAIL: Client cannot reach Server B through tunnel"
  echo "  Response: $HEALTH_B"
  echo ""
  echo "  Debug info:"
  echo "  --- Client WireGuard ---"
  wg show
  echo "  --- Client routes ---"
  ip route
  echo ""
  echo "  --- Tunnel A status ---"
  curl -sf "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/status" \
    -H "X-API-Key: ${SERVER_A_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"
  echo "  --- Tunnel B status ---"
  curl -sf "${SERVER_B_URL}/api/v1/tunnels/${TUNNEL_B_ID}/status" \
    -H "X-API-Key: ${SERVER_B_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"
  exit 1
fi

# Show tunnel stats
echo ""
echo "=== Tunnel Stats ==="
echo "--- Client ---"
wg show
echo ""
echo "--- Tunnel A (on Server A) ---"
curl -sf "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/status" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"
echo ""
echo "--- Tunnel B (on Server B) ---"
curl -sf "${SERVER_B_URL}/api/v1/tunnels/${TUNNEL_B_ID}/status" \
  -H "X-API-Key: ${SERVER_B_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"

echo ""
echo "=== ALL TUNNEL TESTS PASSED ==="
exit 0
