package wireguard

import (
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/acl"
)

// capturedCmds collects iptables commands issued during a test.
type capturedCmds struct {
	mu   sync.Mutex
	cmds []string
}

func (c *capturedCmds) capture(args ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmds = append(c.cmds, strings.Join(args, " "))
	return nil
}

func (c *capturedCmds) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.cmds))
	copy(out, c.cmds)
	return out
}

func (c *capturedCmds) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmds = nil
}

func setupMockIptables(t *testing.T) *capturedCmds {
	t.Helper()
	orig := iptablesCmd
	cap := &capturedCmds{}
	iptablesCmd = cap.capture
	t.Cleanup(func() { iptablesCmd = orig })
	return cap
}

func TestIptablesACLEnforcer_AdminOnly(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	// Only admins, no non-admin policies — should not create ACL chain.
	admins := map[string]bool{"10.0.0.2": true}
	policies := map[string][]acl.CompiledRule{}

	e.OnACLReload(policies, admins)

	// With admins but no policies, it should still build the chain
	// (admins get ACCEPT, then DROP at end for unknown sources).
	cmds := cap.list()
	if len(cmds) == 0 {
		t.Fatal("expected iptables commands to be issued")
	}

	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.2 -j ACCEPT")
	assertContains(t, cmds, "-A WG-ACL-STAGING -j DROP")
	assertContains(t, cmds, "-E WG-ACL-STAGING WG-ACL")
}

func TestIptablesACLEnforcer_NoPeers(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	// No admins, no policies — should do nothing.
	e.OnACLReload(map[string][]acl.CompiledRule{}, map[string]bool{})

	cmds := cap.list()
	if len(cmds) != 0 {
		t.Fatalf("expected no iptables commands, got %d: %v", len(cmds), cmds)
	}
}

func TestIptablesACLEnforcer_SinglePeerTCPRule(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	policies := map[string][]acl.CompiledRule{
		"10.0.0.2": {
			{
				Network:  netip.MustParsePrefix("192.168.1.0/24"),
				Protocol: "tcp",
				PortLow:  80,
				PortHigh: 80,
			},
		},
	}

	e.OnACLReload(policies, map[string]bool{})

	cmds := cap.list()
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.2 -d 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT")
	assertContains(t, cmds, "-A WG-ACL-STAGING -j DROP")
	assertContains(t, cmds, "-A FORWARD -i wg0 -j WG-ACL-STAGING")
	assertContains(t, cmds, "-A FORWARD -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT")
	assertContains(t, cmds, "-E WG-ACL-STAGING WG-ACL")
}

func TestIptablesACLEnforcer_ProtocolAnyWithPorts(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	policies := map[string][]acl.CompiledRule{
		"10.0.0.3": {
			{
				Network:  netip.MustParsePrefix("10.0.0.0/8"),
				Protocol: "any",
				PortLow:  443,
				PortHigh: 443,
			},
		},
	}

	e.OnACLReload(policies, map[string]bool{})

	cmds := cap.list()
	// "any" with ports should generate separate tcp, udp, and icmp rules.
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.3 -d 10.0.0.0/8 -p tcp --dport 443 -j ACCEPT")
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.3 -d 10.0.0.0/8 -p udp --dport 443 -j ACCEPT")
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.3 -d 10.0.0.0/8 -p icmp -j ACCEPT")
}

func TestIptablesACLEnforcer_ProtocolAnyWithoutPorts(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	policies := map[string][]acl.CompiledRule{
		"10.0.0.4": {
			{
				Network:  netip.MustParsePrefix("0.0.0.0/0"),
				Protocol: "any",
			},
		},
	}

	e.OnACLReload(policies, map[string]bool{})

	cmds := cap.list()
	// "any" without ports should generate a single rule without -p.
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.4 -d 0.0.0.0/0 -j ACCEPT")
}

func TestIptablesACLEnforcer_PortRange(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	policies := map[string][]acl.CompiledRule{
		"10.0.0.5": {
			{
				Network:  netip.MustParsePrefix("172.16.0.0/12"),
				Protocol: "udp",
				PortLow:  8000,
				PortHigh: 8999,
			},
		},
	}

	e.OnACLReload(policies, map[string]bool{})

	cmds := cap.list()
	assertContains(t, cmds, "-A WG-ACL-STAGING -s 10.0.0.5 -d 172.16.0.0/12 -p udp --dport 8000:8999 -j ACCEPT")
}

func TestIptablesACLEnforcer_ReloadReplacesChain(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	// First load
	policies := map[string][]acl.CompiledRule{
		"10.0.0.2": {
			{Network: netip.MustParsePrefix("192.168.0.0/16"), Protocol: "any"},
		},
	}
	e.OnACLReload(policies, map[string]bool{})

	// First load should remove blanket rules.
	cmds := cap.list()
	assertContains(t, cmds, "-D FORWARD -i wg0 -j ACCEPT")
	assertContains(t, cmds, "-D FORWARD -o wg0 -j ACCEPT")

	cap.reset()

	// Second load (reload) — should remove old chain jump, not blanket rules.
	policies2 := map[string][]acl.CompiledRule{
		"10.0.0.2": {
			{Network: netip.MustParsePrefix("10.0.0.0/8"), Protocol: "tcp", PortLow: 22, PortHigh: 22},
		},
	}
	e.OnACLReload(policies2, map[string]bool{})

	cmds2 := cap.list()
	assertContains(t, cmds2, "-D FORWARD -i wg0 -j WG-ACL")
	assertContains(t, cmds2, "-F WG-ACL")
	assertContains(t, cmds2, "-X WG-ACL")
	assertContains(t, cmds2, "-A WG-ACL-STAGING -s 10.0.0.2 -d 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT")
	assertContains(t, cmds2, "-E WG-ACL-STAGING WG-ACL")
}

func TestIptablesACLEnforcer_CleanupRestoresBlanket(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	// Activate ACL chain.
	policies := map[string][]acl.CompiledRule{
		"10.0.0.2": {{Network: netip.MustParsePrefix("0.0.0.0/0"), Protocol: "any"}},
	}
	e.OnACLReload(policies, map[string]bool{})
	cap.reset()

	// Cleanup.
	e.Cleanup()

	cmds := cap.list()
	assertContains(t, cmds, "-D FORWARD -i wg0 -j WG-ACL")
	assertContains(t, cmds, "-F WG-ACL")
	assertContains(t, cmds, "-X WG-ACL")
	assertContains(t, cmds, "-A FORWARD -i wg0 -j ACCEPT")
	assertContains(t, cmds, "-A FORWARD -o wg0 -j ACCEPT")
}

func TestIptablesACLEnforcer_CleanupWhenNotActive(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	// Cleanup when not active should be a no-op.
	e.Cleanup()

	cmds := cap.list()
	if len(cmds) != 0 {
		t.Fatalf("expected no iptables commands, got %d: %v", len(cmds), cmds)
	}
}

func TestIptablesACLEnforcer_MixedAdminsAndPolicies(t *testing.T) {
	cap := setupMockIptables(t)
	e := NewIptablesACLEnforcer("wg0")

	admins := map[string]bool{"10.0.0.1": true}
	policies := map[string][]acl.CompiledRule{
		"10.0.0.2": {
			{Network: netip.MustParsePrefix("192.168.1.0/24"), Protocol: "tcp", PortLow: 80, PortHigh: 80},
			{Network: netip.MustParsePrefix("192.168.1.0/24"), Protocol: "tcp", PortLow: 443, PortHigh: 443},
		},
	}

	e.OnACLReload(policies, admins)

	cmds := cap.list()
	// Admin rule should come before peer rules.
	adminIdx := indexOf(cmds, "-A WG-ACL-STAGING -s 10.0.0.1 -j ACCEPT")
	peerIdx := indexOf(cmds, "-A WG-ACL-STAGING -s 10.0.0.2 -d 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT")
	dropIdx := indexOf(cmds, "-A WG-ACL-STAGING -j DROP")

	if adminIdx == -1 || peerIdx == -1 || dropIdx == -1 {
		t.Fatalf("missing expected rules in: %v", cmds)
	}
	if adminIdx >= peerIdx {
		t.Error("admin rule should come before peer rules")
	}
	if peerIdx >= dropIdx {
		t.Error("peer rules should come before DROP")
	}
}

func assertContains(t *testing.T, cmds []string, expected string) {
	t.Helper()
	for _, cmd := range cmds {
		if cmd == expected {
			return
		}
	}
	t.Errorf("expected command %q not found in:\n%s", expected, strings.Join(cmds, "\n"))
}

func indexOf(cmds []string, target string) int {
	for i, cmd := range cmds {
		if cmd == target {
			return i
		}
	}
	return -1
}
