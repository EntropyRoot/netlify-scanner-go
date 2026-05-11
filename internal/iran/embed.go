package iran

import (
	_ "embed"
	"net"
	"strings"
)

//go:embed data/netlify-cidrs.txt
var embeddedCIDRsRaw string

// EmbeddedCIDRs returns parsed CIDR ranges for offline / restricted use.
func EmbeddedCIDRs() []*net.IPNet {
	out := make([]*net.IPNet, 0, 32)
	for _, line := range strings.Split(embeddedCIDRsRaw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// EmbeddedCIDRStrings returns raw CIDR strings (for display/log).
func EmbeddedCIDRStrings() []string {
	out := make([]string, 0, 32)
	for _, line := range strings.Split(embeddedCIDRsRaw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}
