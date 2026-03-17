package domain

import "time"

type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"` // "local" or "oidc"
	CreatedAt time.Time `json:"created_at"`
}

const (
	GroupSourceLocal = "local"
	GroupSourceOIDC  = "oidc"
)
