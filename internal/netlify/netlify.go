package netlify

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	FallbackApexA    = "75.2.60.5"
	ApexLoadBalancer = "apex-loadbalancer.netlify.com"
	NetlifyASN       = 54113
)

var CNAMESuffixes = []string{
	".netlify.app.",
	".netlify.com.",
	".netlifyglobalcdn.com.",
	".nfshost.com.",
}

var HeaderSignals = []string{
	"x-nf-request-id",
	"x-nf-cache",
	"x-nf-edge-cache",
	"x-nf-edge-functions",
}

type Signal struct {
	CNAMEMatch   string `json:"cname_match,omitempty"`
	APEXFallback bool   `json:"apex_fallback,omitempty"`
	HeaderMatch  string `json:"header_match,omitempty"`
	ServerHeader string `json:"server_header,omitempty"`
	TLSSANMatch  string `json:"tls_san_match,omitempty"`
	ASNMatch     bool   `json:"asn_match,omitempty"`
	JARMMatch    string `json:"jarm_match,omitempty"`
}

type Verdict struct {
	Host      string   `json:"host"`
	IsNetlify bool     `json:"is_netlify"`
	Score     int      `json:"score"`
	Addrs     []string `json:"addrs,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
	Signals   Signal   `json:"signals"`
}

type Classifier struct {
	HTTPClient *http.Client
	Resolver   *net.Resolver
	NetlifyIPs map[string]struct{}
	Timeout    time.Duration

	// JARMProbe is an optional hook that returns the JARM hash for a host.
	// When the returned hash is in the known Netlify set the verdict gains
	// +25. The package does not implement JARM itself — wire this to
	// `jarm.ScanWithTLSX` (or your own probe) at the call site.
	JARMProbe func(ctx context.Context, host string) (hash string, ok bool)
}

func NewClassifier(timeout time.Duration) *Classifier {
	return &Classifier{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
				MaxIdleConns:      0,
			},
			Timeout: timeout,
		},
		Resolver: net.DefaultResolver,
		Timeout:  timeout,
	}
}

func (c *Classifier) WithIPSet(ips map[string]struct{}) *Classifier {
	c.NetlifyIPs = ips
	return c
}

func (c *Classifier) Fingerprint(ctx context.Context, host string) Verdict {
	v := Verdict{Host: host}

	rctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	if cname, err := c.Resolver.LookupCNAME(rctx, host); err == nil {
		v.CNAME = cname
		if suf := matchSuffix(cname); suf != "" {
			v.Signals.CNAMEMatch = suf
			v.Score += 50
		}
	}
	if addrs, err := c.Resolver.LookupHost(rctx, host); err == nil {
		v.Addrs = addrs
		for _, a := range addrs {
			if a == FallbackApexA {
				v.Signals.APEXFallback = true
				v.Score += 50
			}
			if _, ok := c.NetlifyIPs[a]; ok {
				v.Signals.ASNMatch = true
				v.Score += 30
			}
		}
	}

	c.probeHTTPS(ctx, &v)

	if c.JARMProbe != nil {
		if hash, ok := c.JARMProbe(ctx, host); ok {
			v.Signals.JARMMatch = hash
			v.Score += 25
		}
	}

	v.IsNetlify = v.Score >= 30
	return v
}

func (c *Classifier) probeHTTPS(ctx context.Context, v *Verdict) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+v.Host, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "netlify-scanner-go/2.0")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	for _, h := range HeaderSignals {
		if resp.Header.Get(h) != "" {
			v.Signals.HeaderMatch = h
			v.Score += 60
			break
		}
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		v.Signals.ServerHeader = srv
		if strings.EqualFold(srv, "Netlify") {
			v.Score += 25
		}
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		for _, name := range resp.TLS.PeerCertificates[0].DNSNames {
			if matchSuffix(name+".") != "" {
				v.Signals.TLSSANMatch = name
				v.Score += 20
				break
			}
		}
	}
}

func matchSuffix(name string) string {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	for _, s := range CNAMESuffixes {
		if strings.HasSuffix(n, s) {
			return strings.TrimSuffix(s, ".")
		}
	}
	return ""
}
