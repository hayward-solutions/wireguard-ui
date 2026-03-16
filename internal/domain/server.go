package domain

import "time"

type ServerConfig struct {
	ID                string    `json:"id"`
	PrivateKey        string    `json:"-"`
	PublicKey         string    `json:"public_key"`
	ListenPort        int       `json:"listen_port"`
	Address           string    `json:"address"`
	DNS               string    `json:"dns"`
	MTU               int       `json:"mtu"`
	PostUp            string    `json:"post_up"`
	PostDown          string    `json:"post_down"`
	Endpoint          string    `json:"endpoint"`
	DefaultAllowedIPs string    `json:"default_allowed_ips"`
	DefaultDNS        string    `json:"default_dns"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
