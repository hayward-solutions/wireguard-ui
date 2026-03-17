package domain

import "time"

type User struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	PasswordHash        string     `json:"-"`
	Name                string     `json:"name"`
	Role                string     `json:"role"`
	LastLogin           *time.Time `json:"last_login,omitempty"`
	FailedLoginAttempts int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`
	CreatedAt           time.Time  `json:"created_at"`
}

const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)
