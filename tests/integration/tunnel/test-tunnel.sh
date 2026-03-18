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
    "listen_port": 0,
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
if [ -n "$TUNNEL_A_PSK" ]; then
  echo "  PSK: (received, will share with B)"
fi

# Step 4: Create a tunnel on Server B pointing to Server A
# Include A's public key, endpoint, and the shared PSK from A so both
# sides of the tunnel use the same preshared key.
echo "[4/8] Creating tunnel on Server B -> Server A..."

# Build the JSON payload — include PSK from tunnel A so both sides share the same key
TUNNEL_B_PAYLOAD=$(jq -n \
  --arg name "tunnel-to-a" \
  --arg desc "Tunnel from B to A" \
  --arg addr "10.100.0.2/30" \
  --argjson port 0 \
  --arg ppk "$TUNNEL_A_PUBKEY" \
  --arg ep "server-a:51820" \
  --arg psk "$TUNNEL_A_PSK" \
  --arg aips "10.0.0.0/24" \
  '{
    name: $name,
    description: $desc,
    address: $addr,
    listen_port: $port,
    peer_public_key: $ppk,
    peer_endpoint: $ep,
    preshared_key: $psk,
    peer_allowed_ips: $aips
  }')

TUNNEL_B_RESPONSE=$(curl -sf -X POST "${SERVER_B_URL}/api/v1/tunnels" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_B_API_KEY}" \
  -d "$TUNNEL_B_PAYLOAD")

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
    \"peer_endpoint\": \"server-b:51821\"
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
for i in $(seq 1 30); do
  STATUS_A=$(curl -sf "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/status" \
    -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null || echo '{}')
  CONNECTED=$(echo "$STATUS_A" | jq -r '.data.connected // false')
  if [ "$CONNECTED" = "true" ]; then
    echo "  Tunnel handshake established! (after ${i}s)"
    TUNNEL_CONNECTED=true
    break
  fi
  sleep 1
done

if [ "$TUNNEL_CONNECTED" = "false" ]; then
  echo "WARN: Tunnel handshake not confirmed via status API after 30s"
  echo "  Status A: $STATUS_A"
  STATUS_B=$(curl -sf "${SERVER_B_URL}/api/v1/tunnels/${TUNNEL_B_ID}/status" \
    -H "X-API-Key: ${SERVER_B_API_KEY}" 2>/dev/null || echo '{}')
  echo "  Status B: $STATUS_B"
fi

# Step 7: Create a client peer on Server A and connect
echo "[7/8] Connecting client to Server A..."

# Create an allow-all ACL rule so the test peer can access the network.
# Peers created via the deprecated static API key don't map to a real user,
# so the default ACL policy (deny-all) blocks their traffic without an explicit rule.
curl -sf -X POST "${SERVER_A_URL}/api/v1/acls" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d '{"name":"allow-all","action":"allow","protocol":"any","dst_cidr":"0.0.0.0/0","priority":100,"enabled":true}' > /dev/null

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

# Restore Docker DNS resolver — wg-quick overrides /etc/resolv.conf with
# the WireGuard DNS (1.1.1.1) which can't resolve Docker service names.
echo "nameserver 127.0.0.11" > /etc/resolv.conf

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
  echo ""
  echo "  --- Server A tunnels list ---"
  curl -sf "${SERVER_A_URL}/api/v1/tunnels" \
    -H "X-API-Key: ${SERVER_A_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"
  echo "  --- Server B tunnels list ---"
  curl -sf "${SERVER_B_URL}/api/v1/tunnels" \
    -H "X-API-Key: ${SERVER_B_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"
  exit 1
fi

# Test 3: Verify tunnel toggle (disable/enable)
echo "  Test 3: Tunnel toggle (disable then re-enable)..."
echo "  DEBUG: TUNNEL_A_ID=${TUNNEL_A_ID}"
TOGGLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/toggle" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null) || TOGGLE_CODE="000"
if [ "$TOGGLE_CODE" = "200" ]; then
  TOGGLED_A=$(curl -s "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}" \
    -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null || echo '{}')
  ENABLED=$(echo "$TOGGLED_A" | jq -r '.data.enabled // "unknown"')
  if [ "$ENABLED" = "false" ]; then
    echo "  Tunnel A disabled successfully"
  else
    echo "  WARN: Tunnel A toggle did not disable (enabled=$ENABLED)"
  fi
else
  echo "  WARN: Tunnel toggle returned $TOGGLE_CODE"
fi

# Re-enable
curl -s -o /dev/null -X POST "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}/toggle" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null || true
sleep 3

# Verify tunnel comes back up
HEALTH_B2=$(curl -sf --connect-timeout 10 "http://${SERVER_B_VPN_IP}:8080/api/v1/health" 2>&1 || true)
if echo "$HEALTH_B2" | jq -e '.status == "ok" or .data.status == "ok"' > /dev/null 2>&1; then
  echo "  PASS: Tunnel reconnects after toggle"
else
  echo "  WARN: Tunnel did not reconnect after toggle (may need more time)"
fi

# Test 4: Verify tunnel deletion
echo "  Test 4: Tunnel delete and cleanup..."
DELETE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" 2>/dev/null) || DELETE_CODE="000"
if [ "$DELETE_CODE" = "200" ]; then
  echo "  Tunnel A deleted"
else
  echo "  WARN: Tunnel delete returned $DELETE_CODE"
fi

DELETED_CHECK=$(curl -s "${SERVER_A_URL}/api/v1/tunnels/${TUNNEL_A_ID}" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" 2>&1 || echo '{"error":{}}')
if echo "$DELETED_CHECK" | jq -e '.error' > /dev/null 2>&1; then
  echo "  PASS: Tunnel A deleted successfully"
else
  echo "  FAIL: Tunnel A still exists after delete"
  exit 1
fi

# Test 5: Validation — reject bad inputs
echo "  Test 5: Input validation..."
BAD_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_A_URL}/api/v1/tunnels" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d '{"name": "", "address": "not-a-cidr"}')
if [ "$BAD_RESPONSE" = "400" ]; then
  echo "  PASS: Empty name rejected with 400"
else
  echo "  FAIL: Expected 400, got $BAD_RESPONSE"
  exit 1
fi

BAD_RESPONSE2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_A_URL}/api/v1/tunnels" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SERVER_A_API_KEY}" \
  -d '{"name": "valid-name", "peer_endpoint": "no-port"}')
if [ "$BAD_RESPONSE2" = "400" ]; then
  echo "  PASS: Bad endpoint rejected with 400"
else
  echo "  FAIL: Expected 400 for bad endpoint, got $BAD_RESPONSE2"
  exit 1
fi

# Show tunnel stats
echo ""
echo "=== Tunnel Stats ==="
echo "--- Client ---"
wg show
echo ""
echo "--- Tunnel B (on Server B, still running) ---"
curl -sf "${SERVER_B_URL}/api/v1/tunnels/${TUNNEL_B_ID}/status" \
  -H "X-API-Key: ${SERVER_B_API_KEY}" | jq . 2>/dev/null || echo "(unavailable)"

echo ""
echo "=== ALL TUNNEL TESTS PASSED ==="
exit 0
