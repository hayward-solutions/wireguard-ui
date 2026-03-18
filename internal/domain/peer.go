package domain

import "time"

type Peer struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	PrivateKey         string    `json:"-"`
	PublicKey          string    `json:"public_key"`
	PresharedKey       string    `json:"-"`
	AllowedIPs         string    `json:"allowed_ips"`
	Address            string    `json:"address"`
	DNS                string    `json:"dns"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	Endpoint           string    `json:"-"` // transient: remote endpoint for tunnel peers (not DB-stored)
	Enabled            bool      `json:"enabled"`
	CreatedBy          string    `json:"created_by"`
	CreatedByName      string    `json:"created_by_name,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type PeerStats struct {
	PublicKey       string    `json:"public_key"`
	Endpoint        string    `json:"endpoint"`
	LastHandshake   time.Time `json:"last_handshake"`
	TransferRx      int64     `json:"transfer_rx"`
	TransferTx      int64     `json:"transfer_tx"`
	Connected       bool      `json:"connected"`
}
