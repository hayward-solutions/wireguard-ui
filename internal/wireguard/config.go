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

// tunnelRemoteConfTmpl is the template for the remote end of a tunnel.
var tunnelRemoteConfTmpl = template.Must(template.New("tunnel-remote").Parse(`[Interface]
# Tunnel: {{ .Tunnel.Name }}
# Paste the private key for the remote end here.
PrivateKey = REPLACE_WITH_REMOTE_PRIVATE_KEY
Address = {{ .RemoteAddress }}
{{- if .Tunnel.ListenPort }}
ListenPort = {{ .Tunnel.ListenPort }}
{{- end }}
{{- if .Tunnel.DNS }}
DNS = {{ .Tunnel.DNS }}
{{- end }}
{{- if .Tunnel.MTU }}
MTU = {{ .Tunnel.MTU }}
{{- end }}

[Peer]
PublicKey = {{ .Tunnel.PublicKey }}
{{- if .Tunnel.PresharedKey }}
PresharedKey = {{ .Tunnel.PresharedKey }}
{{- end }}
{{- if .LocalEndpoint }}
Endpoint = {{ .LocalEndpoint }}
{{- end }}
AllowedIPs = {{ .LocalAllowedIPs }}
PersistentKeepalive = {{ .Tunnel.PersistentKeepalive }}
`))

type tunnelRemoteConfData struct {
	Tunnel          *domain.Tunnel
	RemoteAddress   string // Address for the remote end (e.g. 10.100.0.2/30)
	LocalEndpoint   string // This server's endpoint (for the remote to connect to)
	LocalAllowedIPs string // This server's subnets (what remote should route here)
}

// RenderTunnelRemoteConfig generates a WireGuard .conf file for the remote end of a tunnel.
func RenderTunnelRemoteConfig(tunnel *domain.Tunnel, localEndpoint, localAllowedIPs string) (string, error) {
	// Derive remote address: swap .1 <-> .2 in a /30 or just use the peer's perspective
	remoteAddr := tunnel.Address // The remote gets the "other" side, but we don't know it
	// For simplicity, we show the tunnel address and let the operator adjust

	data := tunnelRemoteConfData{
		Tunnel:          tunnel,
		RemoteAddress:   remoteAddr,
		LocalEndpoint:   localEndpoint,
		LocalAllowedIPs: localAllowedIPs,
	}

	var buf bytes.Buffer
	if err := tunnelRemoteConfTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render tunnel remote config: %w", err)
	}
	return buf.String(), nil
}
