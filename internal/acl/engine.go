package acl

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// PolicyEngine is an in-memory compiled ACL evaluator.
// It maps peer VPN IPs to pre-compiled allow rules for efficient per-connection checks.
// The engine is safe for concurrent use.
type PolicyEngine struct {
	mu       sync.RWMutex
	policies map[string]*userPolicy // peer VPN IP → compiled rules
	admins   map[string]bool        // peer VPN IPs owned by admin users
}

type userPolicy struct {
	rules []compiledRule
}

type compiledRule struct {
	network  netip.Prefix
	protocol string // "any", "tcp", "udp"
	portLow  uint16
	portHigh uint16
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*userPolicy),
		admins:   make(map[string]bool),
	}
}

// Check evaluates whether traffic from srcIP using the given protocol to dstIP:dstPort is allowed.
// Returns true if the traffic should be forwarded, false if it should be denied.
func (e *PolicyEngine) Check(srcIP string, proto string, dstIP netip.Addr, dstPort uint16) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Admin peers bypass all ACLs
	if e.admins[srcIP] {
		return true
	}

	policy, ok := e.policies[srcIP]
	if !ok {
		// Unknown peer — deny by default
		return false
	}

	for _, r := range policy.rules {
		if !r.network.Contains(dstIP) {
			continue
		}
		if r.protocol != domain.ACLProtocolAny && r.protocol != proto {
			continue
		}
		if r.portLow != 0 && (dstPort < r.portLow || dstPort > r.portHigh) {
			continue
		}
		return true
	}

	return false
}

// Reload rebuilds the in-memory policy from the database.
// It loads all peers, users, and ACL rules, compiles them, and swaps atomically.
func (e *PolicyEngine) Reload(ctx context.Context, store database.Store) error {
	peers, err := store.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}

	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	// Build user role lookup and set of user IDs that have peers
	userRoles := make(map[string]string, len(users))
	for _, u := range users {
		userRoles[u.ID] = u.Role
	}

	// Build peer IP → user ID mapping
	type peerInfo struct {
		userID string
		ip     string
	}
	var peerInfos []peerInfo
	userHasPeers := make(map[string]bool)

	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		ip := extractIP(p.Address)
		if ip == "" {
			continue
		}
		peerInfos = append(peerInfos, peerInfo{userID: p.CreatedBy, ip: ip})
		userHasPeers[p.CreatedBy] = true
	}

	// Load effective rules for each non-admin user that has peers
	userRules := make(map[string][]domain.ACLRule)
	for userID := range userHasPeers {
		if userRoles[userID] == domain.RoleAdmin {
			continue
		}
		rules, err := store.GetEffectiveACLRules(ctx, userID)
		if err != nil {
			slog.Error("acl: failed to load rules for user", "user_id", userID, "error", err)
			continue
		}
		userRules[userID] = rules
	}

	// Compile policies
	newPolicies := make(map[string]*userPolicy)
	newAdmins := make(map[string]bool)

	for _, pi := range peerInfos {
		if userRoles[pi.userID] == domain.RoleAdmin {
			newAdmins[pi.ip] = true
			continue
		}

		rules, ok := userRules[pi.userID]
		if !ok {
			// No rules loaded (error above), default to deny
			newPolicies[pi.ip] = &userPolicy{}
			continue
		}

		compiled := make([]compiledRule, 0, len(rules))
		for _, r := range rules {
			cr, err := compileRule(r)
			if err != nil {
				slog.Warn("acl: skipping invalid rule", "rule_id", r.ID, "error", err)
				continue
			}
			compiled = append(compiled, cr)
		}
		newPolicies[pi.ip] = &userPolicy{rules: compiled}
	}

	// Atomic swap
	e.mu.Lock()
	e.policies = newPolicies
	e.admins = newAdmins
	e.mu.Unlock()

	slog.Info("acl: policy reloaded",
		"peers", len(newPolicies)+len(newAdmins),
		"admin_peers", len(newAdmins),
		"policy_peers", len(newPolicies))

	return nil
}

// extractIP extracts the IP address from a CIDR string like "10.0.0.2/32".
func extractIP(address string) string {
	if address == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		// Try as bare IP
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return ""
		}
		return addr.String()
	}
	return prefix.Addr().String()
}

func compileRule(r domain.ACLRule) (compiledRule, error) {
	prefix, err := netip.ParsePrefix(r.DstCIDR)
	if err != nil {
		return compiledRule{}, fmt.Errorf("parse CIDR %q: %w", r.DstCIDR, err)
	}

	cr := compiledRule{
		network:  prefix,
		protocol: r.Protocol,
	}

	if r.DstPorts != "" {
		low, high, err := parsePorts(r.DstPorts)
		if err != nil {
			return compiledRule{}, fmt.Errorf("parse ports %q: %w", r.DstPorts, err)
		}
		cr.portLow = low
		cr.portHigh = high
	}

	return cr, nil
}

// parsePorts parses a port specification: "80", "443", "8000-8999".
func parsePorts(s string) (uint16, uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}

	parts := strings.SplitN(s, "-", 2)
	low, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", parts[0], err)
	}

	if len(parts) == 1 {
		return uint16(low), uint16(low), nil
	}

	high, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", parts[1], err)
	}

	if low > high {
		return 0, 0, fmt.Errorf("port range %d-%d is invalid", low, high)
	}

	return uint16(low), uint16(high), nil
}
