package wireguard

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

var peerConfTmpl = template.Must(template.New("peer").Parse(`[Interface]
PrivateKey = {{ .Peer.PrivateKey }}
Address = {{ .Peer.Address }}
{{- if .DNS }}
DNS = {{ .DNS }}
{{- end }}
{{- if .MTU }}
MTU = {{ .MTU }}
{{- end }}

[Peer]
PublicKey = {{ .Server.PublicKey }}
{{- if .Peer.PresharedKey }}
PresharedKey = {{ .Peer.PresharedKey }}
{{- end }}
Endpoint = {{ .Server.Endpoint }}:{{ .Server.ListenPort }}
AllowedIPs = {{ .Peer.AllowedIPs }}
{{- if .Peer.PersistentKeepalive }}
PersistentKeepalive = {{ .Peer.PersistentKeepalive }}
{{- end }}
`))

type peerConfData struct {
	Peer   *domain.Peer
	Server *domain.ServerConfig
	DNS    string
	MTU    int
}

// RenderPeerConfig generates a WireGuard .conf file for a peer.
func RenderPeerConfig(peer *domain.Peer, server *domain.ServerConfig) (string, error) {
	dns := peer.DNS
	if dns == "" {
		dns = server.DNS
	}

	data := peerConfData{
		Peer:   peer,
		Server: server,
		DNS:    dns,
		MTU:    server.MTU,
	}

	var buf bytes.Buffer
	if err := peerConfTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render peer config: %w", err)
	}
	return buf.String(), nil
}
