package discover

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
)

type Aggressive struct {
	Roots         []string
	SeedHosts     []string
	Concurrency   int
	DialTimeout   time.Duration
	DNSTimeout    time.Duration
	IncludeASN    bool
	MaxASNIPs     int
	MaxRounds     int
	StrictSAN     bool
	SlugMutations bool
	OnEvent       func(AggEvent)
}

type AggEventKind string

const (
	AggSource    AggEventKind = "source"
	AggResolve   AggEventKind = "resolve"
	AggSAN       AggEventKind = "san"
	AggASN       AggEventKind = "asn"
	AggHostFound AggEventKind = "host"
	AggIPFound   AggEventKind = "ip"
	AggRound     AggEventKind = "round"
	AggSummary   AggEventKind = "summary"
	AggSlug      AggEventKind = "slug"
)

type AggEvent struct {
	Kind   AggEventKind
	Source string
	Msg    string
	N      int
}

type AggResult struct {
	Hosts map[string]struct{}
	IPs   *IPSet
	Rounds int
}

func (a *Aggressive) emit(e AggEvent) {
	if a.OnEvent != nil {
		a.OnEvent(e)
	}
}

func (a *Aggressive) Run(ctx context.Context) (*AggResult, error) {
	a.defaults()
	hosts := map[string]struct{}{}
	for _, h := range a.SeedHosts {
		hosts[h] = struct{}{}
	}
	a.harvestRoots(ctx, hosts)

	ips := NewIPSet()
	if a.IncludeASN {
		a.expandASN(ctx, ips)
	}

	for round := 1; round <= a.MaxRounds; round++ {
		a.emit(AggEvent{Kind: AggRound, N: round, Msg: "starting round"})
		ipsBefore := ips.Len()
		hostsBefore := len(hosts)

		if err := a.resolveHosts(ctx, mapKeys(hosts), ips); err != nil {
			return nil, err
		}

		a.harvestSANs(ctx, ips.Sorted(), hosts)

		if a.SlugMutations {
			a.expandSlugs(ctx, hosts)
		}

		ipsAdded := ips.Len() - ipsBefore
		hostsAdded := len(hosts) - hostsBefore
		a.emit(AggEvent{Kind: AggRound, N: round,
			Msg: "round complete",
			Source: "ips=+" + itoa(ipsAdded) + " hosts=+" + itoa(hostsAdded)})

		if ipsAdded == 0 && hostsAdded == 0 {
			break
		}
	}

	a.emit(AggEvent{Kind: AggSummary, N: ips.Len(), Msg: "done"})
	return &AggResult{Hosts: hosts, IPs: ips, Rounds: a.MaxRounds}, nil
}

func (a *Aggressive) defaults() {
	if a.Concurrency <= 0 {
		a.Concurrency = 64
	}
	if a.DNSTimeout == 0 {
		a.DNSTimeout = 4 * time.Second
	}
	if a.DialTimeout == 0 {
		a.DialTimeout = 5 * time.Second
	}
	if a.MaxRounds == 0 {
		a.MaxRounds = 3
	}
}

func (a *Aggressive) harvestRoots(ctx context.Context, hosts map[string]struct{}) {
	if len(a.Roots) == 0 {
		return
	}
	stream := HarvestAll(ctx, a.Roots, DefaultSources, 6)
	for r := range stream {
		if r.Err != nil {
			a.emit(AggEvent{Kind: AggSource, Source: r.Source, Msg: "err: " + r.Err.Error()})
			continue
		}
		a.emit(AggEvent{Kind: AggSource, Source: r.Source, N: len(r.Hosts)})
		for _, h := range r.Hosts {
			if _, ok := hosts[h]; !ok {
				hosts[h] = struct{}{}
				a.emit(AggEvent{Kind: AggHostFound, Msg: h})
			}
		}
	}
}

func (a *Aggressive) expandASN(ctx context.Context, ips *IPSet) {
	a.emit(AggEvent{Kind: AggASN, Source: "AS54113"})
	pfx, err := ASNPrefixes(ctx, netlify.NetlifyASN)
	if err != nil {
		a.emit(AggEvent{Kind: AggASN, Msg: "err: " + err.Error()})
		return
	}
	before := ips.Len()
	ExpandPrefixes(pfx, ips, a.MaxASNIPs)
	a.emit(AggEvent{Kind: AggASN, N: ips.Len() - before})
}

func (a *Aggressive) resolveHosts(ctx context.Context, hosts []string, ips *IPSet) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(a.Concurrency)
	for _, h := range hosts {
		h := h
		g.Go(func() error {
			cctx, cancel := context.WithTimeout(gctx, a.DNSTimeout)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(cctx, h)
			if err != nil {
				return nil
			}
			a.emit(AggEvent{Kind: AggResolve, Msg: h, N: len(addrs)})
			for _, addr := range addrs {
				ip := net.ParseIP(addr)
				if ip == nil || ip.To4() == nil {
					continue
				}
				if ips.Add(addr, "sni:"+h) {
					a.emit(AggEvent{Kind: AggIPFound, Msg: addr})
				}
			}
			return nil
		})
	}
	return g.Wait()
}

// harvestSANs in StrictSAN mode only adds names from a peer cert that already
// matches a Netlify suffix — the *opposite* of the v2 behavior, which polluted
// the corpus with random non-Netlify certs.
func (a *Aggressive) harvestSANs(ctx context.Context, ips []string, hosts map[string]struct{}) {
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(a.Concurrency)
	dialer := &net.Dialer{Timeout: a.DialTimeout}
	for _, ip := range ips {
		ip := ip
		g.Go(func() error {
			cctx, cancel := context.WithTimeout(gctx, a.DialTimeout)
			defer cancel()
			conn, err := dialer.DialContext(cctx, "tcp", ip+":443")
			if err != nil {
				return nil
			}
			defer conn.Close()
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			_ = tc.SetDeadline(time.Now().Add(a.DialTimeout))
			if err := tc.Handshake(); err != nil {
				return nil
			}
			defer tc.Close()
			state := tc.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				return nil
			}
			cert := state.PeerCertificates[0]

			if a.StrictSAN {
				netlifyCert := false
				for _, n := range cert.DNSNames {
					if matchSuffix(strings.ToLower(n) + ".") {
						netlifyCert = true
						break
					}
				}
				if !netlifyCert {
					return nil
				}
			}

			added := 0
			mu.Lock()
			for _, name := range cert.DNSNames {
				name = strings.TrimPrefix(strings.ToLower(name), "*.")
				if name == "" {
					continue
				}
				if _, ok := hosts[name]; !ok {
					hosts[name] = struct{}{}
					added++
				}
			}
			mu.Unlock()
			if added > 0 {
				a.emit(AggEvent{Kind: AggSAN, Source: ip, N: added})
			}
			return nil
		})
	}
	_ = g.Wait()
}

func (a *Aggressive) expandSlugs(ctx context.Context, hosts map[string]struct{}) {
	keys := mapKeys(hosts)
	slugs := ExtractSiteSlugs(keys)
	if len(slugs) == 0 {
		return
	}
	mutated := MutateSlugs(slugs)
	a.emit(AggEvent{Kind: AggSlug, N: len(mutated), Msg: "probing mutated slugs"})
	results := ProbeSlugs(ctx, mutated, a.Concurrency, 5*time.Second)
	for _, r := range results {
		if !r.Live {
			continue
		}
		host := r.Slug + ".netlify.app"
		if _, ok := hosts[host]; !ok {
			hosts[host] = struct{}{}
			a.emit(AggEvent{Kind: AggHostFound, Msg: host})
		}
	}
}

// checkPublicSlugs probes the Netlify dashboard URL for every discovered
// slug and emits an event for those that are publicly accessible (no
// auth required).
func (a *Aggressive) checkPublicSlugs(ctx context.Context, hosts map[string]struct{}) {
	slugs := ExtractSiteSlugs(mapKeys(hosts))
	if len(slugs) == 0 {
		return
	}
	results := CheckPublicAccess(ctx, slugs, a.Concurrency, 5*time.Second)
	for _, r := range results {
		if r.Public {
			a.emit(AggEvent{Kind: AggSlug, Source: r.Slug,
				Msg: "PUBLIC dashboard: " + r.URL})
		}
	}
}

func matchSuffix(name string) bool {
	for _, s := range netlify.CNAMESuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
