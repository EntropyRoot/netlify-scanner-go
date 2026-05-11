package netlify

import (
	_ "embed"
	"strings"
)

//go:embed data/sni-seed.txt
var sniSeedRaw string

//go:embed data/seed-ips.txt
var seedIPsRaw string

func SeedSNIs() []string  { return parseList(sniSeedRaw) }
func SeedIPs() []string   { return parseList(seedIPsRaw) }

func parseList(raw string) []string {
	out := make([]string, 0, 512)
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}
