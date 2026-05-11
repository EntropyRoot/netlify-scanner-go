package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type IPSet struct {
	mu sync.RWMutex
	m  map[string]IPOrigin
}

type IPOrigin struct {
	Via   string
	First time.Time
}

func NewIPSet() *IPSet { return &IPSet{m: map[string]IPOrigin{}} }

func (s *IPSet) Add(ip, via string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[ip]; ok {
		return false
	}
	s.m[ip] = IPOrigin{Via: via, First: time.Now()}
	return true
}

func (s *IPSet) Snapshot() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]struct{}, len(s.m))
	for k := range s.m {
		out[k] = struct{}{}
	}
	return out
}

func (s *IPSet) Sorted() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *IPSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

type Resolver struct {
	R       *net.Resolver
	Timeout time.Duration
	Workers int
}

func (r *Resolver) Resolve(ctx context.Context, hosts []string, set *IPSet, onHost func(string, []string)) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(r.Workers)
	for _, h := range hosts {
		h := h
		g.Go(func() error {
			cctx, cancel := context.WithTimeout(gctx, r.Timeout)
			defer cancel()
			addrs, err := r.R.LookupHost(cctx, h)
			if err != nil {
				return nil
			}
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
					set.Add(a, "sni:"+h)
				}
			}
			if onHost != nil {
				onHost(h, addrs)
			}
			return nil
		})
	}
	return g.Wait()
}

type bgpviewPrefix struct {
	Prefix string `json:"prefix"`
	IP     string `json:"ip"`
	CIDR   int    `json:"cidr"`
}

type bgpviewResp struct {
	Status string `json:"status"`
	Data   struct {
		IPv4 []bgpviewPrefix `json:"ipv4_prefixes"`
	} `json:"data"`
}

func ASNPrefixes(ctx context.Context, asn int) ([]*net.IPNet, error) {
	u := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go/2.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var br bgpviewResp
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	if !strings.EqualFold(br.Status, "ok") {
		return nil, fmt.Errorf("bgpview status=%s", br.Status)
	}
	out := make([]*net.IPNet, 0, len(br.Data.IPv4))
	for _, p := range br.Data.IPv4 {
		_, n, err := net.ParseCIDR(p.Prefix)
		if err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

type ctEntry struct {
	NameValue string `json:"name_value"`
}

func CrtShQuery(ctx context.Context, q string) ([]string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape(q) + "&output=json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go/2.0")
	cl := &http.Client{Timeout: 60 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var entries []ctEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(n), "*."))
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out, nil
}

func ExpandPrefixes(prefixes []*net.IPNet, set *IPSet, max int) {
	count := 0
	for _, p := range prefixes {
		ones, bits := p.Mask.Size()
		if bits-ones > 16 {
			continue
		}
		for ip := p.IP.Mask(p.Mask); p.Contains(ip); incIP(ip) {
			if count >= max {
				return
			}
			set.Add(ip.String(), "asn:"+p.String())
			count++
		}
	}
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
