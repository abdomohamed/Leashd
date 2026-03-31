package dns

import (
	"bufio"
	"net"
	"os"
	"strings"
)

const defaultResolvConfPath = "/etc/resolv.conf"

// SystemNameservers parses /etc/resolv.conf and returns the IPv4 nameserver
// addresses found. IPv6 addresses are silently skipped (the BPF layer is
// IPv4-only). Returns an empty slice if the file is missing or contains no
// usable nameservers.
func SystemNameservers() []net.IP {
	return parseResolvConf(defaultResolvConfPath)
}

// parseResolvConf reads a resolv.conf-formatted file and extracts IPv4
// nameserver addresses.
func parseResolvConf(path string) []net.IP {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var nameservers []net.IP
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			// Skip IPv6 — BPF policy map is IPv4-only.
			continue
		}
		nameservers = append(nameservers, ip.To4())
	}
	return nameservers
}
