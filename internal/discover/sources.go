package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Source struct {
	Name string
	Fn   func(ctx context.Context, root string) ([]string, error)
}

var DefaultSources = []Source{
	{"crt.sh", crtSh},
	{"certspotter", certSpotter},
	{"hackertarget", hackertarget},
	{"alienvault", alienVault},
	{"rapiddns", rapidDNS},
	{"subdomain.center", subdomainCenter},
	{"wayback", wayback},
}

type CacheBackend interface {
	Get(key string, dst any) (bool, error)
	Put(key string, payload any) error
}

func WithCache(c CacheBackend, sources []Source) []Source {
	if c == nil {
		return sources
	}
	out := make([]Source, len(sources))
	for i, s := range sources {
		s := s
		out[i] = Source{
			Name: s.Name,
			Fn: func(ctx context.Context, root string) ([]string, error) {
				key := "harvest:" + s.Name + ":" + root
				var cached []string
				if ok, _ := c.Get(key, &cached); ok {
					return cached, nil
				}
				hosts, err := s.Fn(ctx, root)
				if err == nil && len(hosts) > 0 {
					_ = c.Put(key, hosts)
				}
				return hosts, err
			},
		}
	}
	return out
}

var defaultSourceClient = &http.Client{
	Timeout:   45 * time.Second,
	Transport: &http.Transport{MaxIdleConnsPerHost: 8},
}

func httpGetJSON(ctx context.Context, url string, v interface{}) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go/2.1")
	req.Header.Set("Accept", "application/json")
	resp, err := defaultSourceClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func httpGetText(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go/2.1")
	resp, err := defaultSourceClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

const crtMaxHosts = 250_000

func crtSh(ctx context.Context, root string) ([]string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+root) + "&output=json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "netlify-scanner-go/3.0")
	req.Header.Set("Accept", "application/json")
	resp, err := defaultSourceClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crt.sh: HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 1024)
	for dec.More() {
		var e struct {
			NameValue string `json:"name_value"`
		}
		if err := dec.Decode(&e); err != nil {
			break
		}
		for _, n := range strings.Split(e.NameValue, "\n") {
			h := normalize(n)
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
			if len(out) >= crtMaxHosts {
				return out, nil
			}
		}
	}
	return out, nil
}

func certSpotter(ctx context.Context, root string) ([]string, error) {
	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", root)
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := httpGetJSON(ctx, u, &entries); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries)*4)
	for _, e := range entries {
		for _, n := range e.DNSNames {
			if h := normalize(n); h != "" {
				out = append(out, h)
			}
		}
	}
	return out, nil
}

func hackertarget(ctx context.Context, root string) ([]string, error) {
	body, err := httpGetText(ctx, "https://api.hackertarget.com/hostsearch/?q="+url.QueryEscape(root))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		host, _, _ := strings.Cut(line, ",")
		if h := normalize(host); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func alienVault(ctx context.Context, root string) ([]string, error) {
	u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/hostname/%s/passive_dns", root)
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := httpGetJSON(ctx, u, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.PassiveDNS))
	for _, e := range resp.PassiveDNS {
		if h := normalize(e.Hostname); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func rapidDNS(ctx context.Context, root string) ([]string, error) {
	body, err := httpGetText(ctx, "https://rapiddns.io/subdomain/"+url.PathEscape(root)+"?full=1#result")
	if err != nil {
		return nil, err
	}
	var out []string
	suffix := "." + root
	for _, tok := range strings.Fields(strings.ReplaceAll(body, "<", " <")) {
		tok = strings.Trim(tok, "\"'<>,;:")
		if strings.HasSuffix(tok, suffix) || tok == root {
			if h := normalize(tok); h != "" {
				out = append(out, h)
			}
		}
	}
	return out, nil
}

func subdomainCenter(ctx context.Context, root string) ([]string, error) {
	u := "https://api.subdomain.center/?domain=" + url.QueryEscape(root)
	var arr []string
	if err := httpGetJSON(ctx, u, &arr); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(arr))
	for _, n := range arr {
		if h := normalize(n); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func wayback(ctx context.Context, root string) ([]string, error) {
	u := "https://web.archive.org/cdx/search/cdx?url=*." + url.QueryEscape(root) + "/*&output=json&fl=original&collapse=urlkey"
	body, err := httpGetText(ctx, u)
	if err != nil {
		return nil, err
	}
	var rows [][]string
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rows))
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		u, err := url.Parse(row[0])
		if err != nil {
			continue
		}
		host := normalize(u.Hostname())
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}

func normalize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\n,;") {
		return ""
	}
	return s
}

type HarvestResult struct {
	Source string
	Hosts  []string
	Err    error
}

func HarvestAll(ctx context.Context, roots []string, sources []Source, concurrency int) <-chan HarvestResult {
	if concurrency <= 0 {
		concurrency = 8
	}
	out := make(chan HarvestResult, 32)
	go func() {
		defer close(out)
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(concurrency)
		for _, root := range roots {
			for _, src := range sources {
				root, src := root, src
				g.Go(func() error {
					hosts, err := src.Fn(gctx, root)
					select {
					case out <- HarvestResult{Source: src.Name + "(" + root + ")", Hosts: hosts, Err: err}:
					case <-gctx.Done():
					}
					return nil
				})
			}
		}
		_ = g.Wait()
	}()
	return out
}

func DedupHosts(in <-chan HarvestResult) (map[string]struct{}, []HarvestResult) {
	seen := map[string]struct{}{}
	var report []HarvestResult
	var mu sync.Mutex
	for r := range in {
		mu.Lock()
		report = append(report, HarvestResult{Source: r.Source, Hosts: r.Hosts, Err: r.Err})
		for _, h := range r.Hosts {
			seen[h] = struct{}{}
		}
		mu.Unlock()
	}
	return seen, report
}

func ReadHostsFile(path string) ([]string, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if h := normalize(sc.Text()); h != "" && !strings.HasPrefix(h, "#") {
			out = append(out, h)
		}
	}
	return out, sc.Err()
}
