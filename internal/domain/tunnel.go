package domain

import "time"

type Tunnel struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // "site-to-site" or "point-to-site"
	Description string    `json:"description"`
	Config      string    `json:"config"` // JSON blob
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	TunnelTypeSiteToSite  = "site-to-site"
	TunnelTypePointToSite = "point-to-site"
)
