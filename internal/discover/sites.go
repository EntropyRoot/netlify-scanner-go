package discover

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

var slugFromSAN = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,62})\.netlify\.app$`)

// validSlug enforces Netlify's slug rules: lowercase alphanumerics + hyphens,
// 3..63 chars, must not start or end with a hyphen.
var validSlug = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`)

// ExtractSiteSlugs returns the unique `<slug>` portion of every
// `<slug>.netlify.app` hostname in the input.
func ExtractSiteSlugs(hosts []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, h := range hosts {
		h = strings.TrimPrefix(strings.ToLower(h), "*.")
		if m := slugFromSAN.FindStringSubmatch(h); m != nil {
			if _, ok := seen[m[1]]; !ok {
				seen[m[1]] = struct{}{}
				out = append(out, m[1])
			}
		}
	}
	return out
}

// SiteSlugFromCNAME extracts a slug from a CNAME like `foo.netlify.app.`.
func SiteSlugFromCNAME(cname string) string {
	c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	if m := slugFromSAN.FindStringSubmatch(c); m != nil {
		return m[1]
	}
	return ""
}

// SlugProbeResult is the result of testing a single slug.
type SlugProbeResult struct {
	Slug      string        `json:"slug"`
	Host      string        `json:"host"`
	Live      bool          `json:"live"`
	Status    int           `json:"status,omitempty"`
	NFReqID   string        `json:"nf_request_id,omitempty"`
	Server    string        `json:"server,omitempty"`
	Location  string        `json:"location,omitempty"`
	Latency   time.Duration `json:"-"`
	LatencyMs int64         `json:"latency_ms"`
	Err       string        `json:"err,omitempty"`
}

// Kept for source compatibility. New code should use ProbeSlugs.
type SlugBruteResult = SlugProbeResult

// notLiveStatuses are HTTP status codes that mean "Netlify says this site
// does not exist". Empirically Netlify returns 404 for unknown slugs and
// 410 for sites the user explicitly deleted.
var notLiveStatuses = map[int]bool{
	404: true,
	410: true,
}

// ProbeSlugs HEADs each `<slug>.netlify.app` and decides whether the slug
// corresponds to a real site.
//
// Why HEAD over HTTPS instead of DNS?
//
//	`*.netlify.app` has a wildcard A/CNAME record. `net.LookupHost` and
//	`dnsx` will both happily resolve `definitely-not-a-real-site-12345
//	.netlify.app` to the Netlify edge — so DNS cannot distinguish real
//	sites from invented ones. The edge itself does the lookup and returns
//	404 for unknown slugs, with `x-nf-request-id` always set.
//
// Heuristic:
//
//	HTTP HEAD `https://<slug>.netlify.app/`, no redirect follow.
//	  - `x-nf-request-id` present AND status ∉ {404, 410}  → Live=true
//	  - status ∈ {404, 410}                               → Live=false
//	  - no `x-nf-request-id` (TLS/network/edge issue)     → Live=false, Err set
//
// This produces high-confidence positives (real sites) and low false-positive
// rate. The trade-off is sites that legitimately serve 404 on `/` are missed,
// which is acceptable for recon (those sites are uncommon and unreachable
// anyway).
func ProbeSlugs(ctx context.Context, slugs []string, workers int, timeout time.Duration) []SlugProbeResult {
	if workers <= 0 {
		workers = 32
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:     false,
			MaxIdleConnsPerHost:   workers,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	out := make([]SlugProbeResult, len(slugs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for i, s := range slugs {
		i, s := i, s
		g.Go(func() error {
			out[i] = probeOne(gctx, client, s, timeout)
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func probeOne(ctx context.Context, client *http.Client, slug string, timeout time.Duration) SlugProbeResult {
	start := time.Now()
	r := SlugProbeResult{Slug: slug, Host: slug + ".netlify.app"}
	defer func() {
		r.Latency = time.Since(start)
		r.LatencyMs = r.Latency.Milliseconds()
	}()
	if !validSlug.MatchString(slug) {
		r.Err = "invalid slug"
		return r
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodHead, "https://"+r.Host+"/", nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "netlify-scanner-go/3.0 slug-probe")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer resp.Body.Close()
	// Drain a small body in case server kept the connection open.
	_, _ = io.CopyN(io.Discard, resp.Body, 64)

	r.Status = resp.StatusCode
	r.NFReqID = resp.Header.Get("x-nf-request-id")
	r.Server = resp.Header.Get("Server")
	r.Location = resp.Header.Get("Location")

	// Without x-nf-request-id the response didn't traverse Netlify's edge —
	// almost certainly a transient/network error, not a real signal.
	if r.NFReqID == "" {
		r.Err = "no x-nf-request-id"
		return r
	}
	if notLiveStatuses[r.Status] {
		return r
	}
	r.Live = true
	return r
}

// BruteforceSlugs is the legacy entry point. It now delegates to ProbeSlugs
// (HTTP-based) instead of the old DNS-only check, which was useless against
// Netlify's wildcard DNS.
func BruteforceSlugs(ctx context.Context, slugs []string, workers int, timeout time.Duration) []SlugProbeResult {
	return ProbeSlugs(ctx, slugs, workers, timeout)
}

// defaultSuffixes / defaultPrefixes are the canonical mutation lists. Kept
// small (~14 each) so the cartesian explosion stays manageable for an
// average corpus.
var (
	defaultSuffixes = []string{
		"", "-dev", "-staging", "-prod", "-preview",
		"-test", "-demo", "-app", "-docs", "-site",
		"-www", "-api", "-admin", "-internal",
		"-beta", "-canary", "-next", "-old", "-new",
		"-v2", "-v3",
	}
	defaultPrefixes = []string{
		"", "dev-", "staging-", "prod-", "preview-",
		"test-", "demo-", "app-", "docs-", "www-",
		"api-", "admin-", "beta-",
	}
)

// MutateSlugs expands each input slug with a small set of prefix/suffix
// permutations. Output is unique and length-filtered (3..63 chars).
func MutateSlugs(slugs []string) []string {
	return MutateSlugsWith(slugs, defaultPrefixes, defaultSuffixes)
}

// MutateSlugsWith lets callers supply their own affix lists.
func MutateSlugsWith(slugs, prefixes, suffixes []string) []string {
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}
	if len(suffixes) == 0 {
		suffixes = []string{""}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(slugs)*len(prefixes)*len(suffixes))
	for _, s := range slugs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		for _, pre := range prefixes {
			for _, suf := range suffixes {
				cand := pre + s + suf
				if !validSlug.MatchString(cand) {
					continue
				}
				if _, ok := seen[cand]; ok {
					continue
				}
				seen[cand] = struct{}{}
				out = append(out, cand)
			}
		}
	}
	return out
}

// LoadWordlist reads slug candidates from a file (one per line, # comments).
// Entries are normalized and validated; invalid lines are silently dropped.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		s := strings.ToLower(strings.TrimSpace(sc.Text()))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		// Strip ".netlify.app" if user pasted full hostnames.
		s = strings.TrimSuffix(s, ".netlify.app")
		if !validSlug.MatchString(s) {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, sc.Err()
}

// FilterLive returns only the slugs whose probe result was Live=true.
func FilterLive(results []SlugProbeResult) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		if r.Live {
			out = append(out, r.Host)
		}
	}
	return out
}

// PublicAccessResult records whether a Netlify dashboard page for a site
// slug is publicly accessible (no auth required). Public access usually
// means the team has misconfigured visibility — useful recon signal.
type PublicAccessResult struct {
	Slug      string `json:"slug"`
	URL       string `json:"url"`
	Status    int    `json:"status"`
	Public    bool   `json:"public"`
	Latency   int64  `json:"latency_ms"`
	Err       string `json:"err,omitempty"`
}

// CheckPublicAccess HEADs `https://app.netlify.com/sites/<slug>` and reports
// whether the dashboard page returns without redirecting to login. The slug
// is whatever came out of `SiteSlugFromCNAME` for a host whose CNAME points
// at the Netlify edge.
func CheckPublicAccess(ctx context.Context, slugs []string, workers int, timeout time.Duration) []PublicAccessResult {
	if workers <= 0 {
		workers = 16
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	out := make([]PublicAccessResult, len(slugs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for i, s := range slugs {
		i, s := i, s
		g.Go(func() error {
			start := time.Now()
			r := PublicAccessResult{Slug: s, URL: "https://app.netlify.com/sites/" + s}
			defer func() { r.Latency = time.Since(start).Milliseconds(); out[i] = r }()
			req, err := http.NewRequestWithContext(gctx, http.MethodHead, r.URL, nil)
			if err != nil {
				r.Err = err.Error()
				return nil
			}
			req.Header.Set("User-Agent", "netlify-scanner-go public-access-probe")
			resp, err := client.Do(req)
			if err != nil {
				r.Err = err.Error()
				return nil
			}
			defer resp.Body.Close()
			r.Status = resp.StatusCode
			// 200 means publicly accessible. 302/303 to /login or 401 means private.
			r.Public = resp.StatusCode == 200
			return nil
		})
	}
	_ = g.Wait()
	return out
}
