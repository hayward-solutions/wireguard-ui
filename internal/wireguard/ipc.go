package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// resolveEndpoint resolves a hostname:port endpoint to ip:port format.
// WireGuard's IPC protocol requires IP addresses, not hostnames.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, nil // not host:port format, return as-is
	}

	// If host is already an IP, return as-is
	if net.ParseIP(host) != nil {
		return endpoint, nil
	}

	// Resolve hostname to IP
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("failed to set endpoint %s: %w", endpoint, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("failed to set endpoint %s: no addresses found", endpoint)
	}

	return net.JoinHostPort(ips[0], port), nil
}

// keyToHex converts a base64-encoded WireGuard key to the hex format used by the IPC protocol.
func keyToHex(base64Key string) (string, error) {
	key, err := wgtypes.ParseKey(base64Key)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}

// buildIpcConfig builds an IPC configuration string for the server.
func buildIpcConfig(cfg *domain.ServerConfig) (string, error) {
	hexKey, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hexKey)
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	b.WriteString("replace_peers=true\n")
	return b.String(), nil
}

// buildIpcPeer builds an IPC peer configuration block.
func buildIpcPeer(p *domain.Peer) (string, error) {
	hexPub, err := keyToHex(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hexPub)

	if p.Endpoint != "" {
		resolved, err := resolveEndpoint(p.Endpoint)
		if err != nil {
			return "", fmt.Errorf("resolve endpoint: %w", err)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", resolved)
	}

	if p.PresharedKey != "" {
		hexPsk, err := keyToHex(p.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", hexPsk)
	}

	for _, cidr := range parseAllowedIPStrings(p.Address) {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}

	if p.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
	}

	return b.String(), nil
}

// buildIpcRemovePeer builds an IPC block to remove a peer by public key.
func buildIpcRemovePeer(publicKey string) (string, error) {
	hexPub, err := keyToHex(publicKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("public_key=%s\nremove=true\n", hexPub), nil
}

// parseIpcStats parses the output of device.IpcGet() into PeerStats.
func parseIpcStats(ipcOutput string) ([]domain.PeerStats, error) {
	var stats []domain.PeerStats
	var current *domain.PeerStats

	for _, line := range strings.Split(ipcOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch key {
		case "public_key":
			// Convert hex back to base64 for consistency with the rest of the app
			raw, err := hex.DecodeString(val)
			if err != nil {
				return nil, fmt.Errorf("decode public key hex: %w", err)
			}
			var keyArr wgtypes.Key
			copy(keyArr[:], raw)
			stats = append(stats, domain.PeerStats{PublicKey: keyArr.String()})
			current = &stats[len(stats)-1]

		case "endpoint":
			if current != nil {
				current.Endpoint = val
			}

		case "last_handshake_time_sec":
			if current != nil {
				sec, _ := strconv.ParseInt(val, 10, 64)
				if sec > 0 {
					current.LastHandshake = time.Unix(sec, 0)
				}
			}

		case "last_handshake_time_nsec":
			if current != nil && !current.LastHandshake.IsZero() {
				nsec, _ := strconv.ParseInt(val, 10, 64)
				current.LastHandshake = current.LastHandshake.Add(time.Duration(nsec) * time.Nanosecond)
			}

		case "rx_bytes":
			if current != nil {
				current.TransferRx, _ = strconv.ParseInt(val, 10, 64)
			}

		case "tx_bytes":
			if current != nil {
				current.TransferTx, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}

	// Set connected status
	for i := range stats {
		stats[i].Connected = !stats[i].LastHandshake.IsZero() && time.Since(stats[i].LastHandshake) < 3*time.Minute
	}

	return stats, nil
}

// parseAllowedIPStrings splits a comma-separated address string into trimmed CIDR strings.
func parseAllowedIPStrings(address string) []string {
	var result []string
	for _, s := range strings.Split(address, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
