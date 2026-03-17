package domain

import "time"

type ACLRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Priority    int       `json:"priority"`      // lower = evaluated first
	Action      string    `json:"action"`         // "allow" (default-deny model)
	Protocol    string    `json:"protocol"`       // "any", "tcp", "udp"
	DstCIDR     string    `json:"dst_cidr"`       // single CIDR, e.g. "10.0.0.0/24"
	DstPorts    string    `json:"dst_ports"`       // "" (all), "80", "443", "8000-8999"
	GroupID     *string   `json:"group_id"`        // mutually exclusive with UserID
	UserID      *string   `json:"user_id"`         // mutually exclusive with GroupID
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	ACLActionAllow = "allow"

	ACLProtocolAny = "any"
	ACLProtocolTCP = "tcp"
	ACLProtocolUDP = "udp"
)
