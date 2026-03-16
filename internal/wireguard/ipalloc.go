package wireguard

import (
	"fmt"
	"net"
)

// AllocateIP finds the next available IP address in the subnet, given a list of already-used addresses.
func AllocateIP(subnet string, usedAddresses []string) (string, error) {
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("parse subnet %q: %w", subnet, err)
	}

	used := make(map[string]bool)
	for _, addr := range usedAddresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			ip = net.ParseIP(addr)
		}
		if ip != nil {
			used[ip.String()] = true
		}
	}

	// Also mark the network address (server) as used
	serverIP, _, _ := net.ParseCIDR(subnet)
	if serverIP != nil {
		used[serverIP.String()] = true
	}

	// Iterate through the subnet to find the next free IP
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	for inc(ip); network.Contains(ip); inc(ip) {
		// Skip broadcast address for IPv4
		if ip[len(ip)-1] == 255 {
			continue
		}
		if !used[ip.String()] {
			ones, _ := network.Mask.Size()
			return fmt.Sprintf("%s/%d", ip.String(), ones), nil
		}
	}

	return "", fmt.Errorf("no available IP addresses in subnet %s", subnet)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
