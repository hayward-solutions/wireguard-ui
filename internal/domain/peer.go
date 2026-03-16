package domain

import "time"

type Peer struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Email              string    `json:"email"`
	PrivateKey         string    `json:"-"`
	PublicKey          string    `json:"public_key"`
	PresharedKey       string    `json:"-"`
	AllowedIPs         string    `json:"allowed_ips"`
	Address            string    `json:"address"`
	DNS                string    `json:"dns"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	Enabled            bool      `json:"enabled"`
	CreatedBy          string    `json:"created_by"`
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
