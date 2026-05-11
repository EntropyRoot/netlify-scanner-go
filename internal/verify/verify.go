package verify

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
	Confirmed   Status = "confirmed"
	NotNetlify  Status = "not-netlify"
	Unreachable Status = "unreachable"
)

type IPResult struct {
	IP           string   `json:"ip"`
	Status       Status   `json:"status"`
	TLSReached   bool     `json:"tls_reached"`
	HTTPReached  bool     `json:"http_reached"`
	CertCN       string   `json:"cert_cn,omitempty"`
	CertSANMatch string   `json:"cert_san_match,omitempty"`
	NFRequestID  string   `json:"nf_request_id,omitempty"`
	ServerHeader string   `json:"server,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	Latency      string   `json:"latency,omitempty"`
	Err          string   `json:"err,omitempty"`
}

type SNIResult struct {
	Host         string   `json:"host"`
	Status       Status   `json:"status"`
	Addrs        []string `json:"addrs,omitempty"`
	CNAME        string   `json:"cname,omitempty"`
	HTTPReached  bool     `json:"http_reached"`
	NFRequestID  string   `json:"nf_request_id,omitempty"`
	CertSANMatch string   `json:"cert_san_match,omitempty"`
	Latency      string   `json:"latency,omitempty"`
	Err          string   `json:"err,omitempty"`
}

type Report struct {
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  time.Time   `json:"finished_at"`
	IPs         []IPResult  `json:"ips,omitempty"`
	SNIs        []SNIResult `json:"snis,omitempty"`
	IPCounts    map[Status]int `json:"ip_counts"`
	SNICounts   map[Status]int `json:"sni_counts"`
}

type Verifier struct {
	DialTimeout time.Duration
	HTTPTimeout time.Duration
	Workers     int
	OnIP        func(IPResult)
	OnSNI       func(SNIResult)

	dialer *net.Dialer
	client *http.Client
}

func New(workers int) *Verifier {
	if workers <= 0 {
		workers = 64
	}
	v := &Verifier{
		DialTimeout: 4 * time.Second,
		HTTPTimeout: 6 * time.Second,
		Workers:     workers,
	}
	v.dialer = &net.Dialer{Timeout: v.DialTimeout}
	v.client = &http.Client{
		Timeout: v.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return v
}

func (v *Verifier) IPs(ctx context.Context, ips []string) []IPResult {
	out := make([]IPResult, len(ips))
	var idx int64
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(v.Workers)
	for i, ip := range ips {
		i, ip := i, ip
		g.Go(func() error {
			r := v.IP(gctx, ip)
			out[i] = r
			mu.Lock()
			idx++
			mu.Unlock()
			if v.OnIP != nil {
				v.OnIP(r)
			}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func (v *Verifier) IP(ctx context.Context, ip string) IPResult {
	start := time.Now()
	r := IPResult{IP: ip, Status: Unreachable}

	conn, err := v.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		r.Err = err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	defer conn.Close()
	r.TLSReached = true

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(v.DialTimeout))
	if err := tc.Handshake(); err != nil {
		r.Err = "tls: " + err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	defer tc.Close()

	if state := tc.ConnectionState(); len(state.PeerCertificates) > 0 {
		certClassify(state.PeerCertificates[0], &r)
	}

	if r.CertSANMatch != "" {
		r.Status = Confirmed
		r.Latency = time.Since(start).String()
		return r
	}

	v.probeHTTP(ctx, "https://"+ip, &r)
	if r.NFRequestID != "" || strings.EqualFold(r.ServerHeader, "Netlify") {
		r.Status = Confirmed
	} else if r.HTTPReached {
		r.Status = NotNetlify
	}
	r.Latency = time.Since(start).String()
	return r
}

func (v *Verifier) SNIs(ctx context.Context, hosts []string) []SNIResult {
	out := make([]SNIResult, len(hosts))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(v.Workers)
	for i, h := range hosts {
		i, h := i, h
		g.Go(func() error {
			r := v.SNI(gctx, h)
			out[i] = r
			if v.OnSNI != nil {
				v.OnSNI(r)
			}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func (v *Verifier) SNI(ctx context.Context, host string) SNIResult {
	start := time.Now()
	r := SNIResult{Host: host, Status: Unreachable}

	resolver := net.DefaultResolver
	rctx, cancel := context.WithTimeout(ctx, v.DialTimeout)
	defer cancel()
	if cname, err := resolver.LookupCNAME(rctx, host); err == nil {
		r.CNAME = cname
	}
	addrs, err := resolver.LookupHost(rctx, host)
	if err != nil {
		r.Err = "dns: " + err.Error()
		r.Latency = time.Since(start).String()
		return r
	}
	r.Addrs = addrs

	v.probeHTTPSNI(ctx, host, &r)
	if r.NFRequestID != "" || r.CertSANMatch != "" {
		r.Status = Confirmed
	} else if r.HTTPReached {
		r.Status = NotNetlify
	}
	r.Latency = time.Since(start).String()
	return r
}

func (v *Verifier) probeHTTP(ctx context.Context, url string, r *IPResult) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "netlify-scanner-go/3.0 verifier")
	resp, err := v.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	r.HTTPReached = true
	r.NFRequestID = resp.Header.Get("x-nf-request-id")
	r.ServerHeader = resp.Header.Get("Server")
}

func (v *Verifier) probeHTTPSNI(ctx context.Context, host string, r *SNIResult) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "netlify-scanner-go/3.0 verifier")
	resp, err := v.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	r.HTTPReached = true
	r.NFRequestID = resp.Header.Get("x-nf-request-id")
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		for _, name := range resp.TLS.PeerCertificates[0].DNSNames {
			if matched := matchNetlifySAN(name); matched != "" {
				r.CertSANMatch = matched
				break
			}
		}
	}
}

func certClassify(c *x509.Certificate, r *IPResult) {
	r.CertCN = c.Subject.CommonName
	r.SANs = c.DNSNames
	for _, name := range c.DNSNames {
		if m := matchNetlifySAN(name); m != "" {
			r.CertSANMatch = m
			return
		}
	}
}

func matchNetlifySAN(name string) string {
	n := strings.TrimPrefix(strings.ToLower(name), "*.") + "."
	for _, suf := range netlify.CNAMESuffixes {
		if strings.HasSuffix(n, suf) {
			return strings.TrimSuffix(suf, ".")
		}
	}
	return ""
}

func Summarize(ips []IPResult, snis []SNIResult) Report {
	r := Report{
		IPs:       ips,
		SNIs:      snis,
		IPCounts:  map[Status]int{},
		SNICounts: map[Status]int{},
	}
	for _, x := range ips {
		r.IPCounts[x.Status]++
	}
	for _, x := range snis {
		r.SNICounts[x.Status]++
	}
	sort.Slice(r.IPs, func(i, j int) bool { return r.IPs[i].IP < r.IPs[j].IP })
	sort.Slice(r.SNIs, func(i, j int) bool { return r.SNIs[i].Host < r.SNIs[j].Host })
	return r
}

func WriteReport(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func FilterConfirmedIPs(ips []IPResult) []string {
	out := make([]string, 0, len(ips))
	for _, x := range ips {
		if x.Status == Confirmed {
			out = append(out, x.IP)
		}
	}
	return out
}

func FilterConfirmedSNIs(snis []SNIResult) []string {
	out := make([]string, 0, len(snis))
	for _, x := range snis {
		if x.Status == Confirmed {
			out = append(out, x.Host)
		}
	}
	return out
}

func ReadLines(r io.Reader) []string {
	b, _ := io.ReadAll(r)
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

var _ = fmt.Stringer(nil)
