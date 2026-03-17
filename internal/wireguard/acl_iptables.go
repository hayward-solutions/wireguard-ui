package wireguard

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/hayward-solutions/wireguard-ui/internal/acl"
)

const (
	aclChainName    = "WG-ACL"
	aclStagingChain = "WG-ACL-STAGING"
)

// IptablesACLEnforcer translates compiled ACL policies into iptables FORWARD chain
// rules scoped to the WireGuard interface. It implements acl.ReloadListener and is
// notified by the PolicyEngine after each reload.
type IptablesACLEnforcer struct {
	interfaceName string
	mu            sync.Mutex
	active        bool // whether WG-ACL chain is currently installed
}

// NewIptablesACLEnforcer creates an enforcer for the given WireGuard interface.
func NewIptablesACLEnforcer(interfaceName string) *IptablesACLEnforcer {
	return &IptablesACLEnforcer{
		interfaceName: interfaceName,
	}
}

// OnACLReload implements acl.ReloadListener. It translates the compiled policies
// into iptables rules using a staging chain that is swapped in atomically.
func (e *IptablesACLEnforcer) OnACLReload(policies map[string][]acl.CompiledRule, admins map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If no non-admin policies exist, remove ACL chain and restore blanket rules.
	if len(policies) == 0 && len(admins) == 0 {
		if e.active {
			e.removeACLChain()
			e.restoreBlanketRules()
			e.active = false
		}
		return
	}

	// Build the staging chain with per-peer rules.
	if err := e.buildAndSwapChain(policies, admins); err != nil {
		slog.Error("acl iptables: failed to apply rules", "error", err)
		return
	}

	slog.Info("acl iptables: rules applied",
		"interface", e.interfaceName,
		"policy_peers", len(policies),
		"admin_peers", len(admins))
}

// Cleanup removes all ACL-related iptables rules and restores blanket FORWARD rules.
// Called on manager shutdown.
func (e *IptablesACLEnforcer) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.active {
		e.removeACLChain()
		e.restoreBlanketRules()
		e.active = false
		slog.Info("acl iptables: cleaned up", "interface", e.interfaceName)
	}
}

// buildAndSwapChain creates a staging chain, populates it, and atomically swaps it in.
func (e *IptablesACLEnforcer) buildAndSwapChain(policies map[string][]acl.CompiledRule, admins map[string]bool) error {
	// Clean up any leftover staging chain from a previous failed attempt.
	_ = iptablesCmd("-F", aclStagingChain)
	_ = iptablesCmd("-X", aclStagingChain)

	// Create staging chain.
	if err := iptablesCmd("-N", aclStagingChain); err != nil {
		return fmt.Errorf("create staging chain: %w", err)
	}

	// Admin peers: unrestricted access.
	adminIPs := sortedKeys(admins)
	for _, ip := range adminIPs {
		if err := iptablesCmd("-A", aclStagingChain, "-s", ip, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("add admin rule for %s: %w", ip, err)
		}
	}

	// Per-peer ACL rules.
	peerIPs := sortedMapKeys(policies)
	for _, peerIP := range peerIPs {
		rules := policies[peerIP]
		for _, r := range rules {
			if err := e.addCompiledRule(aclStagingChain, peerIP, r); err != nil {
				return fmt.Errorf("add rule for peer %s: %w", peerIP, err)
			}
		}
	}

	// Default deny at end of chain.
	if err := iptablesCmd("-A", aclStagingChain, "-j", "DROP"); err != nil {
		return fmt.Errorf("add default deny: %w", err)
	}

	// Swap phase: remove old rules, install new chain.
	if e.active {
		// Remove existing FORWARD jump to old chain.
		_ = iptablesCmd("-D", "FORWARD", "-i", e.interfaceName, "-j", aclChainName)
		_ = iptablesCmd("-D", "FORWARD", "-o", e.interfaceName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	} else {
		// Remove blanket FORWARD ACCEPT rules that were installed at startup.
		_ = iptablesCmd("-D", "FORWARD", "-i", e.interfaceName, "-j", "ACCEPT")
		_ = iptablesCmd("-D", "FORWARD", "-o", e.interfaceName, "-j", "ACCEPT")
	}

	// Install jump to staging chain.
	if err := iptablesCmd("-A", "FORWARD", "-i", e.interfaceName, "-j", aclStagingChain); err != nil {
		return fmt.Errorf("add FORWARD jump to staging: %w", err)
	}

	// Allow return traffic (ESTABLISHED,RELATED) on outbound direction.
	if err := iptablesCmd("-A", "FORWARD", "-o", e.interfaceName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add return traffic rule: %w", err)
	}

	// Flush and delete old chain, rename staging.
	if e.active {
		_ = iptablesCmd("-F", aclChainName)
		_ = iptablesCmd("-X", aclChainName)
	}

	if err := iptablesCmd("-E", aclStagingChain, aclChainName); err != nil {
		return fmt.Errorf("rename staging chain: %w", err)
	}

	e.active = true
	return nil
}

// addCompiledRule adds iptables rules for a single compiled ACL rule.
func (e *IptablesACLEnforcer) addCompiledRule(chain, srcIP string, r acl.CompiledRule) error {
	dst := r.Network.String()

	if r.PortLow == 0 && r.PortHigh == 0 {
		// No port restriction.
		if r.Protocol == "any" {
			// Single rule without -p.
			return iptablesCmd("-A", chain, "-s", srcIP, "-d", dst, "-j", "ACCEPT")
		}
		return iptablesCmd("-A", chain, "-s", srcIP, "-d", dst, "-p", r.Protocol, "-j", "ACCEPT")
	}

	// Port restriction requires -p; "any" protocol needs separate tcp + udp rules.
	portSpec := portToString(r.PortLow, r.PortHigh)

	protocols := []string{r.Protocol}
	if r.Protocol == "any" {
		protocols = []string{"tcp", "udp"}
	}

	for _, proto := range protocols {
		if err := iptablesCmd("-A", chain, "-s", srcIP, "-d", dst, "-p", proto, "--dport", portSpec, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	// When protocol is "any" and ports are specified, also allow ICMP (which has no ports).
	if r.Protocol == "any" {
		if err := iptablesCmd("-A", chain, "-s", srcIP, "-d", dst, "-p", "icmp", "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	return nil
}

// removeACLChain removes the FORWARD jump and the WG-ACL chain.
func (e *IptablesACLEnforcer) removeACLChain() {
	_ = iptablesCmd("-D", "FORWARD", "-i", e.interfaceName, "-j", aclChainName)
	_ = iptablesCmd("-D", "FORWARD", "-o", e.interfaceName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	_ = iptablesCmd("-F", aclChainName)
	_ = iptablesCmd("-X", aclChainName)
}

// restoreBlanketRules re-adds the blanket FORWARD ACCEPT rules for the WireGuard interface.
func (e *IptablesACLEnforcer) restoreBlanketRules() {
	if err := iptablesCmd("-A", "FORWARD", "-i", e.interfaceName, "-j", "ACCEPT"); err != nil {
		slog.Warn("acl iptables: failed to restore forward-in rule", "error", err)
	}
	if err := iptablesCmd("-A", "FORWARD", "-o", e.interfaceName, "-j", "ACCEPT"); err != nil {
		slog.Warn("acl iptables: failed to restore forward-out rule", "error", err)
	}
}

// portToString formats a port or port range for iptables --dport.
func portToString(low, high uint16) string {
	if low == high {
		return fmt.Sprintf("%d", low)
	}
	return fmt.Sprintf("%d:%d", low, high)
}

// sortedKeys returns the keys of a map[string]bool in sorted order for deterministic output.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedMapKeys returns the keys of a map[string][]acl.CompiledRule in sorted order.
func sortedMapKeys(m map[string][]acl.CompiledRule) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Verify interface compliance at compile time.
var _ acl.ReloadListener = (*IptablesACLEnforcer)(nil)
