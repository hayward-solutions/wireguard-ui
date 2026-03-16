package wireguard

import (
	"bytes"
	"fmt"
	"strings"
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
Endpoint = {{ .Endpoint }}
AllowedIPs = {{ .Peer.AllowedIPs }}
{{- if .Peer.PersistentKeepalive }}
PersistentKeepalive = {{ .Peer.PersistentKeepalive }}
{{- end }}
`))

type peerConfData struct {
	Peer     *domain.Peer
	Server   *domain.ServerConfig
	Endpoint string
	DNS      string
	MTU      int
}

// RenderPeerConfig generates a WireGuard .conf file for a peer.
func RenderPeerConfig(peer *domain.Peer, server *domain.ServerConfig) (string, error) {
	dns := peer.DNS
	if dns == "" {
		dns = server.DNS
	}

	// If the endpoint already includes a port (host:port), use it as-is.
	// Otherwise append the server's listen port.
	endpoint := server.Endpoint
	if !strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("%s:%d", endpoint, server.ListenPort)
	}

	data := peerConfData{
		Peer:     peer,
		Server:   server,
		Endpoint: endpoint,
		DNS:      dns,
		MTU:      server.MTU,
	}

	var buf bytes.Buffer
	if err := peerConfTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render peer config: %w", err)
	}
	return buf.String(), nil
}
