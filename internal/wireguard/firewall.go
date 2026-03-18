package wireguard

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// ApplyFirewallRules applies structured iptables rules without shell execution.
// Each iptables command is called directly with individual arguments.
func ApplyFirewallRules(cfg *domain.FirewallConfig, serverAddress, interfaceName string) error {
	if cfg == nil {
		return nil
	}

	source := cfg.NATSource
	if source == "" {
		source = serverAddress
	}
	outIface := cfg.NATOutInterface
	if outIface == "" {
		outIface = "eth+"
	}

	if cfg.EnableNAT {
		if err := iptablesCmd("-t", "nat", "-A", "POSTROUTING", "-s", source, "-o", outIface, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("add NAT masquerade rule: %w", err)
		}
	}

	if cfg.EnableForwarding {
		// When peer isolation is enabled (default), drop peer-to-peer traffic
		// (wg→wg) before adding the broader ACCEPT rules.
		if !cfg.AllowPeerToPeer {
			if err := iptablesCmd("-A", "FORWARD", "-i", interfaceName, "-o", interfaceName, "-j", "DROP"); err != nil {
				return fmt.Errorf("add peer-isolation rule: %w", err)
			}
		}
		if err := iptablesCmd("-A", "FORWARD", "-i", interfaceName, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("add forward-in rule: %w", err)
		}
		if err := iptablesCmd("-A", "FORWARD", "-o", interfaceName, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("add forward-out rule: %w", err)
		}
	}

	slog.Info("firewall rules applied",
		"nat", cfg.EnableNAT,
		"forwarding", cfg.EnableForwarding,
		"allow_peer_to_peer", cfg.AllowPeerToPeer,
		"source", source,
		"out_interface", outIface,
		"wg_interface", interfaceName)
	return nil
}

// RemoveFirewallRules removes the structured iptables rules.
func RemoveFirewallRules(cfg *domain.FirewallConfig, serverAddress, interfaceName string) error {
	if cfg == nil {
		return nil
	}

	source := cfg.NATSource
	if source == "" {
		source = serverAddress
	}
	outIface := cfg.NATOutInterface
	if outIface == "" {
		outIface = "eth+"
	}

	if cfg.EnableNAT {
		if err := iptablesCmd("-t", "nat", "-D", "POSTROUTING", "-s", source, "-o", outIface, "-j", "MASQUERADE"); err != nil {
			slog.Warn("failed to remove NAT masquerade rule", "error", err)
		}
	}

	if cfg.EnableForwarding {
		if !cfg.AllowPeerToPeer {
			if err := iptablesCmd("-D", "FORWARD", "-i", interfaceName, "-o", interfaceName, "-j", "DROP"); err != nil {
				slog.Warn("failed to remove peer-isolation rule", "error", err)
			}
		}
		if err := iptablesCmd("-D", "FORWARD", "-i", interfaceName, "-j", "ACCEPT"); err != nil {
			slog.Warn("failed to remove forward-in rule", "error", err)
		}
		if err := iptablesCmd("-D", "FORWARD", "-o", interfaceName, "-j", "ACCEPT"); err != nil {
			slog.Warn("failed to remove forward-out rule", "error", err)
		}
	}

	slog.Info("firewall rules removed",
		"nat", cfg.EnableNAT,
		"forwarding", cfg.EnableForwarding,
		"allow_peer_to_peer", cfg.AllowPeerToPeer,
		"wg_interface", interfaceName)
	return nil
}

// iptablesCmd calls the iptables binary directly with individual arguments (no shell).
// It is a variable to allow injection in tests.
var iptablesCmd = func(args ...string) error {
	slog.Debug("executing iptables", "args", args)
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// IsDefaultFirewallScript returns true if the PostUp script matches the auto-generated
// default NAT masquerade + forwarding pattern from first-boot initialization.
func IsDefaultFirewallScript(postUp, address, interfaceName string) bool {
	expected := fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o eth+ -j MASQUERADE; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT",
		address, interfaceName, interfaceName)
	return postUp == expected
}

// RunScriptIfAllowed executes a shell script only if custom scripts are enabled.
// Logs all execution attempts with script hash, type, and duration.
func RunScriptIfAllowed(script string, scriptType string, allowed bool) error {
	hash := scriptHash(script)

	if !allowed {
		slog.Warn("custom script execution blocked (set ALLOW_CUSTOM_SCRIPTS=true to enable)",
			"type", scriptType,
			"script_hash", hash)
		return fmt.Errorf("custom script execution is disabled (set ALLOW_CUSTOM_SCRIPTS=true to enable)")
	}

	slog.Info("executing custom script",
		"type", scriptType,
		"script_hash", hash)

	start := time.Now()
	cmd := exec.Command("sh", "-c", script)
	out, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if err != nil {
		slog.Warn("custom script failed",
			"type", scriptType,
			"script_hash", hash,
			"duration", duration,
			"error", err,
			"output", strings.TrimSpace(string(out)))
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}

	slog.Info("custom script completed",
		"type", scriptType,
		"script_hash", hash,
		"duration", duration)
	return nil
}

// scriptHash returns a short SHA-256 hash prefix for audit logging.
func scriptHash(script string) string {
	h := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%x", h[:8])
}

// ApplyTunnelRoutes adds kernel routes and iptables FORWARD rules to route traffic
// from the main WireGuard interface to a tunnel interface for specific subnets.
func ApplyTunnelRoutes(mainIface, tunnelIface string, subnets []string) error {
	for _, subnet := range subnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		// Add kernel route: traffic to this subnet goes via the tunnel interface
		if err := ipRouteCmd("add", subnet, "dev", tunnelIface); err != nil {
			slog.Warn("failed to add tunnel route (may already exist)", "subnet", subnet, "iface", tunnelIface, "error", err)
		}

		// Allow forwarding from main WG interface to tunnel interface for this subnet
		if err := iptablesCmd("-A", "FORWARD", "-i", mainIface, "-o", tunnelIface, "-d", subnet, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("add tunnel forward-in rule for %s: %w", subnet, err)
		}

		// Allow return traffic from tunnel interface back to main WG interface
		if err := iptablesCmd("-A", "FORWARD", "-i", tunnelIface, "-o", mainIface, "-s", subnet, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("add tunnel forward-out rule for %s: %w", subnet, err)
		}
	}

	slog.Info("tunnel routes applied",
		"main_iface", mainIface,
		"tunnel_iface", tunnelIface,
		"subnets", subnets)
	return nil
}

// RemoveTunnelRoutes removes kernel routes and iptables FORWARD rules for a tunnel.
func RemoveTunnelRoutes(mainIface, tunnelIface string, subnets []string) error {
	for _, subnet := range subnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		if err := ipRouteCmd("del", subnet, "dev", tunnelIface); err != nil {
			slog.Warn("failed to remove tunnel route", "subnet", subnet, "iface", tunnelIface, "error", err)
		}
		if err := iptablesCmd("-D", "FORWARD", "-i", mainIface, "-o", tunnelIface, "-d", subnet, "-j", "ACCEPT"); err != nil {
			slog.Warn("failed to remove tunnel forward-in rule", "subnet", subnet, "error", err)
		}
		if err := iptablesCmd("-D", "FORWARD", "-i", tunnelIface, "-o", mainIface, "-s", subnet, "-j", "ACCEPT"); err != nil {
			slog.Warn("failed to remove tunnel forward-out rule", "subnet", subnet, "error", err)
		}
	}

	slog.Info("tunnel routes removed",
		"main_iface", mainIface,
		"tunnel_iface", tunnelIface,
		"subnets", subnets)
	return nil
}

// ipRouteCmd calls the ip route binary directly with individual arguments.
var ipRouteCmd = func(args ...string) error {
	fullArgs := append([]string{"route"}, args...)
	slog.Debug("executing ip route", "args", fullArgs)
	out, err := exec.Command("ip", fullArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s: %w", strings.Join(fullArgs, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
