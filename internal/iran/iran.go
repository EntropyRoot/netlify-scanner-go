// Package iran implements a restricted-internet workflow tailored for users
// scanning from networks (e.g. inside Iran) where many SNIs and IPs are
// blocked or throttled. It only uses the Go standard library — no external
// tools (subfinder, dnsx, httpx, naabu, nuclei) are required.
//
// Flow:
//
//  1. Probe a list of seed SNIs over TLS (SNI included). The ones whose
//     handshake completes AND whose cert chains to a Netlify SAN are
//     considered "reachable from this network". Their resolved A records
//     feed step 2.
//  2. Probe candidate IPs on :443. TCP-connect, then TLS handshake WITHOUT
//     SNI (and again with SNI=apex-loadbalancer.netlify.com). Record cert
//     SANs. Any SAN that matches a Netlify suffix is harvested.
//  3. For every harvested SAN, re-probe over HTTPS with that SNI — to learn
//     which of the discovered SNIs are *also* reachable from this network.
//
// The final report links three sets:
//
//	openSNIs        — SNI works directly from this network
//	openIPs         — IP:443 is reachable AND serves a Netlify cert
//	usableSNIxIP    — pairs of (SNI, IP) that BOTH responded
package iran

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
)

type Status string

const (
	Open     Status = "open"
	Blocked  Status = "blocked"
	Filtered Status = "filtered" // TCP/TLS succeeded but cert is not Netlify
)

type SNIProbe struct {
	SNI      string   `json:"sni"`
	Status   Status   `json:"status"`
	Addrs    []string `json:"addrs,omitempty"`
	CertSAN  string   `json:"cert_san,omitempty"`
	NFReqID  string   `json:"nf_request_id,omitempty"`
	Server   string   `json:"server,omitempty"`
	Latency  string   `json:"latency,omitempty"`
	Err      string   `json:"err,omitempty"`
}

type IPProbe struct {
	IP       string   `json:"ip"`
	Status   Status   `json:"status"`
	SANs     []string `json:"sans,omitempty"`
	CertCN   string   `json:"cert_cn,omitempty"`
	MatchSAN string   `json:"match_san,omitempty"`
	NFReqID  string   `json:"nf_request_id,omitempty"`
	Server   string   `json:"server,omitempty"`
	Latency  string   `json:"latency,omitempty"`
	Err      string   `json:"err,omitempty"`
}

type Pair struct {
	SNI string `json:"sni"`
	IP  string `json:"ip"`
}

type Report struct {
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   time.Time  `json:"finished_at"`
	SNIProbes    []SNIProbe `json:"sni_probes"`
	IPProbes     []IPProbe  `json:"ip_probes"`
	OpenSNIs     []string   `json:"open_snis"`
	OpenIPs      []string   `json:"open_ips"`
	HarvestedSNI []string   `json:"harvested_snis"`
	Pairs        []Pair     `json:"usable_pairs"`
}

type Scanner struct {
	Workers     int
	DialTimeout time.Duration
	HTTPTimeout time.Duration

	// RatePPS caps probe starts per second across all goroutines. 0 disables
	// the limiter (useful when local network can keep up).
	RatePPS int64

	OnSNI    func(SNIProbe)
	OnIP     func(IPProbe)
	OnLog    func(string)
	OnStage  func(stage string, total int)
	OnReport func(Report)

	dialer  *net.Dialer
	client  *http.Client
	limiter *rateLimiter
	once    sync.Once
}

type rateLimiter struct {
	tickets chan struct{}
	stop    chan struct{}
}

func newRateLimiter(pps int64) *rateLimiter {
	if pps <= 0 {
		return nil
	}
	r := &rateLimiter{
		tickets: make(chan struct{}, int(pps)),
		stop:    make(chan struct{}),
	}
	go func() {
		t := time.NewTicker(time.Second / time.Duration(pps))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case r.tickets <- struct{}{}:
				default:
				}
			case <-r.stop:
				return
			}
		}
	}()
	return r
}

func (r *rateLimiter) Wait(ctx context.Context) {
	if r == nil {
		return
	}
	select {
	case <-r.tickets:
	case <-ctx.Done():
	}
}

func (r *rateLimiter) Close() {
	if r == nil {
		return
	}
	close(r.stop)
}

func New(workers int) *Scanner {
	if workers <= 0 {
		workers = 32
	}
	s := &Scanner{
		Workers:     workers,
		DialTimeout: 5 * time.Second,
		HTTPTimeout: 6 * time.Second,
	}
	s.init()
	return s
}

func (s *Scanner) init() {
	s.once.Do(func() {
		if s.DialTimeout == 0 {
			s.DialTimeout = 5 * time.Second
		}
		if s.HTTPTimeout == 0 {
			s.HTTPTimeout = 6 * time.Second
		}
		s.dialer = &net.Dialer{Timeout: s.DialTimeout}
		s.client = &http.Client{
			Timeout: s.HTTPTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
				DialContext:       (&net.Dialer{Timeout: s.DialTimeout}).DialContext,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		s.limiter = newRateLimiter(s.RatePPS)
	})
}

// Close releases the rate limiter goroutine.
func (s *Scanner) Close() { s.limiter.Close() }

// SetRate atomically swaps the rate limiter. Pass 0 to disable.
func (s *Scanner) SetRate(pps int64) {
	old := s.limiter
	s.limiter = newRateLimiter(pps)
	old.Close()
}

func (s *Scanner) log(f string, a ...any) {
	if s.OnLog != nil {
		s.OnLog(fmt.Sprintf(f, a...))
	}
}

func (s *Scanner) emitStage(name string, total int) {
	if s.OnStage != nil {
		s.OnStage(name, total)
	}
}

// Run executes the full restricted-network workflow.
func (s *Scanner) Run(ctx context.Context, snis, ips []string) Report {
	s.init()
	rep := Report{StartedAt: time.Now()}

	s.emitStage("sni-seed", len(snis))
	s.log("step 1/3: probing %d seed SNIs", len(snis))
	rep.SNIProbes = s.ProbeSNIs(ctx, snis)
	openSNI := map[string]struct{}{}
	for _, p := range rep.SNIProbes {
		if p.Status == Open {
			openSNI[p.SNI] = struct{}{}
			for _, a := range p.Addrs {
				if !contains(ips, a) {
					ips = append(ips, a)
				}
			}
		}
	}
	rep.OpenSNIs = keys(openSNI)

	s.emitStage("ip-probe", len(ips))
	s.log("step 2/3: probing %d candidate IPs", len(ips))
	rep.IPProbes = s.ProbeIPs(ctx, ips)
	harvested := map[string]struct{}{}
	for _, p := range rep.IPProbes {
		if p.Status == Open {
			rep.OpenIPs = append(rep.OpenIPs, p.IP)
			for _, san := range p.SANs {
				san = strings.TrimPrefix(strings.ToLower(san), "*.")
				if matchNetlifySAN(san) != "" {
					harvested[san] = struct{}{}
				}
			}
		}
	}
	rep.HarvestedSNI = keys(harvested)
	sort.Strings(rep.OpenIPs)

	// Step 3: which harvested SANs are themselves reachable from here?
	newSNIs := make([]string, 0, len(harvested))
	for h := range harvested {
		if _, ok := openSNI[h]; ok {
			continue
		}
		// Skip wildcard SANs.
		if strings.HasPrefix(h, "*") {
			continue
		}
		newSNIs = append(newSNIs, h)
	}
	s.emitStage("san-reprobe", len(newSNIs))
	s.log("step 3/3: re-probing %d harvested SANs", len(newSNIs))
	extra := s.ProbeSNIs(ctx, newSNIs)
	rep.SNIProbes = append(rep.SNIProbes, extra...)
	for _, p := range extra {
		if p.Status == Open {
			openSNI[p.SNI] = struct{}{}
		}
	}
	rep.OpenSNIs = keys(openSNI)
	sort.Strings(rep.OpenSNIs)
	sort.Strings(rep.HarvestedSNI)

	// Build SNI×IP usable pairs.
	openIPSet := map[string]struct{}{}
	for _, ip := range rep.OpenIPs {
		openIPSet[ip] = struct{}{}
	}
	for _, p := range rep.SNIProbes {
		if p.Status != Open {
			continue
		}
		for _, a := range p.Addrs {
			if _, ok := openIPSet[a]; ok {
				rep.Pairs = append(rep.Pairs, Pair{SNI: p.SNI, IP: a})
			}
		}
	}
	sort.Slice(rep.Pairs, func(i, j int) bool {
		if rep.Pairs[i].SNI == rep.Pairs[j].SNI {
			return rep.Pairs[i].IP < rep.Pairs[j].IP
		}
		return rep.Pairs[i].SNI < rep.Pairs[j].SNI
	})

	rep.FinishedAt = time.Now()
	return rep
}

// ProbeSNIs probes a batch of hostnames in parallel.
func (s *Scanner) ProbeSNIs(ctx context.Context, snis []string) []SNIProbe {
	s.init()
	out := make([]SNIProbe, len(snis))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.Workers)
	for i, h := range snis {
		i, h := i, h
		g.Go(func() error {
			r := s.probeSNI(gctx, h)
			out[i] = r
			if s.OnSNI != nil {
				s.OnSNI(r)
			}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func (s *Scanner) probeSNI(ctx context.Context, host string) SNIProbe {
	s.limiter.Wait(ctx)
	start := time.Now()
	r := SNIProbe{SNI: host, Status: Blocked}
	rctx, cancel := context.WithTimeout(ctx, s.DialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(rctx, host)
	if err != nil {
		r.Err = "dns: " + err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	r.Addrs = addrs

	var lastErr error
	for _, ip := range addrs {
		conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		if err != nil {
			lastErr = err
			continue
		}
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(s.DialTimeout))
		if err := tc.Handshake(); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			for _, n := range st.PeerCertificates[0].DNSNames {
				if m := matchNetlifySAN(strings.TrimPrefix(strings.ToLower(n), "*.")); m != "" {
					r.CertSAN = n
					break
				}
			}
		}
		_ = tc.Close()
		conn.Close()
		lastErr = nil
		break
	}
	if lastErr != nil {
		r.Err = "tls: " + lastErr.Error()
		r.Latency = time.Since(start).String()
		return r
	}

	// HTTPS HEAD to confirm reachability and harvest Netlify headers.
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go iran-mode")
	if resp, err := s.client.Do(req); err == nil {
		resp.Body.Close()
		r.NFReqID = resp.Header.Get("x-nf-request-id")
		r.Server = resp.Header.Get("Server")
	}

	if r.CertSAN != "" || r.NFReqID != "" || strings.EqualFold(r.Server, "Netlify") {
		r.Status = Open
	} else {
		r.Status = Filtered
	}
	r.Latency = time.Since(start).String()
	return r
}

// ProbeIPs probes a batch of IPs in parallel.
func (s *Scanner) ProbeIPs(ctx context.Context, ips []string) []IPProbe {
	s.init()
	out := make([]IPProbe, len(ips))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.Workers)
	for i, ip := range ips {
		i, ip := i, ip
		g.Go(func() error {
			r := s.probeIP(gctx, ip)
			out[i] = r
			if s.OnIP != nil {
				s.OnIP(r)
			}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func (s *Scanner) probeIP(ctx context.Context, ip string) IPProbe {
	s.limiter.Wait(ctx)
	start := time.Now()
	r := IPProbe{IP: ip, Status: Blocked}

	conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		r.Err = "dial: " + err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	defer conn.Close()

	// First try with SNI=apex-loadbalancer (Netlify is more likely to send a
	// useful cert for this name); fall back to no-SNI.
	tc := tls.Client(conn, &tls.Config{ServerName: netlify.ApexLoadBalancer, InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(s.DialTimeout))
	if err := tc.Handshake(); err != nil {
		r.Err = "tls: " + err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	defer tc.Close()
	classifyCert(tc.ConnectionState().PeerCertificates, &r)

	// HEAD over IP — we don't really care about the host header here.
	url := "https://" + ip
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	req.Header.Set("Host", netlify.ApexLoadBalancer)
	req.Header.Set("User-Agent", "netlify-scanner-go iran-mode")
	if resp, err := s.client.Do(req); err == nil {
		resp.Body.Close()
		r.NFReqID = resp.Header.Get("x-nf-request-id")
		r.Server = resp.Header.Get("Server")
	}

	if r.MatchSAN != "" || r.NFReqID != "" || strings.EqualFold(r.Server, "Netlify") {
		r.Status = Open
	} else {
		r.Status = Filtered
	}
	r.Latency = time.Since(start).String()
	return r
}

func classifyCert(chain []*x509.Certificate, r *IPProbe) {
	if len(chain) == 0 {
		return
	}
	c := chain[0]
	r.CertCN = c.Subject.CommonName
	r.SANs = c.DNSNames
	for _, n := range c.DNSNames {
		if m := matchNetlifySAN(strings.TrimPrefix(strings.ToLower(n), "*.")); m != "" {
			r.MatchSAN = m
			return
		}
	}
}

func matchNetlifySAN(name string) string {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	for _, suf := range netlify.CNAMESuffixes {
		if strings.HasSuffix(n, suf) {
			return strings.TrimSuffix(suf, ".")
		}
	}
	return ""
}

// WriteReport emits the JSON report.
func WriteReport(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
