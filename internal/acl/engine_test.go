package acl

import (
	"net/netip"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.0.0.1/32", "10.0.0.1"},
		{"10.0.0.2/24", "10.0.0.2"},
		{"10.0.0.3", "10.0.0.3"},
		{"", ""},
		{"not-an-ip", ""},
	}
	for _, tt := range tests {
		got := extractIP(tt.input)
		if got != tt.want {
			t.Errorf("extractIP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		input   string
		low     uint16
		high    uint16
		wantErr bool
	}{
		{"80", 80, 80, false},
		{"443", 443, 443, false},
		{"8000-8999", 8000, 8999, false},
		{"", 0, 0, false},
		{"abc", 0, 0, true},
		{"100-50", 0, 0, true}, // low > high
		{"99999", 0, 0, true},  // exceeds uint16
	}
	for _, tt := range tests {
		low, high, err := parsePorts(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parsePorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && (low != tt.low || high != tt.high) {
			t.Errorf("parsePorts(%q) = (%d, %d), want (%d, %d)", tt.input, low, high, tt.low, tt.high)
		}
	}
}

func TestCompileRule(t *testing.T) {
	rule := domain.ACLRule{
		DstCIDR:  "10.0.0.0/8",
		Protocol: "tcp",
		DstPorts: "80-443",
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}
	if cr.protocol != "tcp" {
		t.Errorf("protocol = %q, want %q", cr.protocol, "tcp")
	}
	if cr.portLow != 80 || cr.portHigh != 443 {
		t.Errorf("ports = (%d, %d), want (80, 443)", cr.portLow, cr.portHigh)
	}
	if !cr.network.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("network should contain 10.1.2.3")
	}
	if cr.network.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Error("network should not contain 192.168.1.1")
	}
}

func TestCompileRuleInvalidCIDR(t *testing.T) {
	rule := domain.ACLRule{DstCIDR: "not-a-cidr", Protocol: "tcp"}
	_, err := compileRule(rule)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestCheckAdminBypass(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.admins["10.0.0.1"] = true
	e.mu.Unlock()

	// Admin should be allowed to reach anything
	if !e.Check("10.0.0.1", "tcp", netip.MustParseAddr("192.168.1.1"), 22) {
		t.Error("admin peer should bypass ACLs")
	}
}

func TestCheckUnknownPeerDenied(t *testing.T) {
	e := NewPolicyEngine()

	if e.Check("10.0.0.99", "tcp", netip.MustParseAddr("192.168.1.1"), 80) {
		t.Error("unknown peer should be denied")
	}
}

func TestCheckDefaultDeny(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{rules: []compiledRule{}}
	e.mu.Unlock()

	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("192.168.1.1"), 80) {
		t.Error("peer with no rules should be denied (default deny)")
	}
}

func TestCheckAllowCIDR(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("192.168.1.0/24"),
				protocol: domain.ACLProtocolAny,
			},
		},
	}
	e.mu.Unlock()

	// Should allow within CIDR
	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("192.168.1.50"), 80) {
		t.Error("should allow traffic within allowed CIDR")
	}

	// Should deny outside CIDR
	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("10.1.0.1"), 80) {
		t.Error("should deny traffic outside allowed CIDR")
	}
}

func TestCheckProtocolFilter(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("0.0.0.0/0"),
				protocol: domain.ACLProtocolTCP,
			},
		},
	}
	e.mu.Unlock()

	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("8.8.8.8"), 443) {
		t.Error("should allow TCP traffic")
	}
	if e.Check("10.0.0.2", "udp", netip.MustParseAddr("8.8.8.8"), 53) {
		t.Error("should deny UDP when only TCP is allowed")
	}
}

func TestCheckPortFilter(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("0.0.0.0/0"),
				protocol: domain.ACLProtocolAny,
				portLow:  80,
				portHigh: 443,
			},
		},
	}
	e.mu.Unlock()

	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 80) {
		t.Error("should allow port 80")
	}
	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 443) {
		t.Error("should allow port 443")
	}
	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 200) {
		t.Error("should allow port 200 (within range)")
	}
	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 22) {
		t.Error("should deny port 22 (below range)")
	}
	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 8080) {
		t.Error("should deny port 8080 (above range)")
	}
}

func TestCheckAllPortsWhenZero(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("0.0.0.0/0"),
				protocol: domain.ACLProtocolAny,
				portLow:  0,
				portHigh: 0,
			},
		},
	}
	e.mu.Unlock()

	// portLow == 0 means all ports allowed
	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 22) {
		t.Error("should allow any port when portLow is 0")
	}
	if !e.Check("10.0.0.2", "udp", netip.MustParseAddr("1.2.3.4"), 53) {
		t.Error("should allow any port when portLow is 0")
	}
}

func TestCheckMultipleRulesFirstMatch(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("10.0.0.0/8"),
				protocol: domain.ACLProtocolTCP,
				portLow:  443,
				portHigh: 443,
			},
			{
				network:  netip.MustParsePrefix("192.168.0.0/16"),
				protocol: domain.ACLProtocolAny,
			},
		},
	}
	e.mu.Unlock()

	// Matches first rule
	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("10.1.2.3"), 443) {
		t.Error("should match first rule (10/8 TCP 443)")
	}
	// Doesn't match first rule (wrong port), no second match for 10/8
	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("10.1.2.3"), 80) {
		t.Error("should deny: 10/8 only allows port 443")
	}
	// Matches second rule
	if !e.Check("10.0.0.2", "udp", netip.MustParseAddr("192.168.1.1"), 53) {
		t.Error("should match second rule (192.168/16 any)")
	}
	// Matches no rules
	if e.Check("10.0.0.2", "tcp", netip.MustParseAddr("8.8.8.8"), 53) {
		t.Error("should deny: no rule covers 8.8.8.8")
	}
}

func TestCheckProtocolAnyMatchesBoth(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("0.0.0.0/0"),
				protocol: domain.ACLProtocolAny,
			},
		},
	}
	e.mu.Unlock()

	if !e.Check("10.0.0.2", "tcp", netip.MustParseAddr("1.2.3.4"), 80) {
		t.Error("protocol 'any' should match TCP")
	}
	if !e.Check("10.0.0.2", "udp", netip.MustParseAddr("1.2.3.4"), 53) {
		t.Error("protocol 'any' should match UDP")
	}
}

func TestCheckConcurrentSafe(t *testing.T) {
	e := NewPolicyEngine()
	e.mu.Lock()
	e.admins["10.0.0.1"] = true
	e.policies["10.0.0.2"] = &userPolicy{
		rules: []compiledRule{
			{
				network:  netip.MustParsePrefix("192.168.0.0/16"),
				protocol: domain.ACLProtocolAny,
			},
		},
	}
	e.mu.Unlock()

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			e.Check("10.0.0.1", "tcp", netip.MustParseAddr("1.2.3.4"), 80)
			e.Check("10.0.0.2", "tcp", netip.MustParseAddr("192.168.1.1"), 80)
			e.Check("10.0.0.99", "tcp", netip.MustParseAddr("1.2.3.4"), 80)
			done <- true
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}
