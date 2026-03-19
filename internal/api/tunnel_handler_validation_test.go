package api

import (
	"strings"
	"testing"
)

func TestValidateTunnelName(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid simple", input: "my-tunnel", wantErr: false},
		{name: "valid single char", input: "a", wantErr: false},
		{name: "valid mixed", input: "a_b-c123", wantErr: false},
		{name: "valid starts with digit", input: "1tunnel", wantErr: false},
		{name: "empty", input: "", wantErr: true},
		{name: "starts with hyphen", input: "-bad", wantErr: true},
		{name: "starts with underscore", input: "_bad", wantErr: true},
		{name: "64 chars too long", input: strings.Repeat("a", 64), wantErr: true},
		{name: "63 chars max valid", input: strings.Repeat("a", 63), wantErr: false},
		{name: "contains space", input: "a b", wantErr: true},
		{name: "contains slash", input: "a/b", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTunnelName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTunnelName(%q): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCIDRList(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "single CIDR", input: "10.0.0.0/24", wantErr: false},
		{name: "two CIDRs", input: "10.0.0.0/24, 192.168.0.0/16", wantErr: false},
		{name: "empty string", input: "", wantErr: false},
		{name: "not a CIDR", input: "not-a-cidr", wantErr: true},
		{name: "IP without prefix", input: "10.0.0.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIDRList(tt.input, "test_field")
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCIDRList(%q): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid hostname", input: "host.com:51820", wantErr: false},
		{name: "valid IP", input: "1.2.3.4:443", wantErr: false},
		{name: "empty string", input: "", wantErr: false},
		{name: "missing port", input: "host.com", wantErr: true},
		{name: "empty host", input: ":51820", wantErr: true},
		{name: "port zero", input: "host.com:0", wantErr: true},
		{name: "port too high", input: "host.com:99999", wantErr: true},
		{name: "port not a number", input: "host.com:abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEndpoint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEndpoint(%q): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateListenPort(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   int
		wantErr bool
	}{
		{name: "zero", input: 0, wantErr: false},
		{name: "one", input: 1, wantErr: false},
		{name: "typical", input: 51820, wantErr: false},
		{name: "max", input: 65535, wantErr: false},
		{name: "negative", input: -1, wantErr: true},
		{name: "over max", input: 65536, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateListenPort(%d): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDNS(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "single IP", input: "1.1.1.1", wantErr: false},
		{name: "two IPs", input: "1.1.1.1, 8.8.8.8", wantErr: false},
		{name: "empty string", input: "", wantErr: false},
		{name: "not an IP", input: "not-an-ip", wantErr: true},
		{name: "invalid octets", input: "999.999.999.999", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDNS(%q): got err=%v, want err=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}
