package netlifyapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const baseURL = "https://api.netlify.com/api/v1"

type Client struct {
	Token  string
	HTTP   *http.Client
}

func New(token string) *Client {
	return &Client{
		Token: token,
		HTTP:  &http.Client{Timeout: 20 * time.Second},
	}
}

type Site struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	SSLURL        string    `json:"ssl_url"`
	AdminURL      string    `json:"admin_url"`
	CustomDomain  string    `json:"custom_domain"`
	DomainAliases []string  `json:"domain_aliases"`
	Account       string    `json:"account_name"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (c *Client) do(ctx context.Context, method, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "netlify-scanner-go/3.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("netlify API: 401 unauthorized — check token")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("netlify API %s: HTTP %d", path, resp.StatusCode)
	}
	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func (c *Client) ListSites(ctx context.Context) ([]Site, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("no Netlify API token (NETLIFY_AUTH_TOKEN)")
	}
	var all []Site
	page := 1
	for {
		var batch []Site
		err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/sites?per_page=100&page=%d", page), &batch)
		if err != nil {
			return all, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
		page++
	}
	return all, nil
}

func (c *Client) FindSiteByDomain(ctx context.Context, domain string) (*Site, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	sites, err := c.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	for i := range sites {
		s := &sites[i]
		if strings.EqualFold(s.CustomDomain, domain) {
			return s, nil
		}
		for _, a := range s.DomainAliases {
			if strings.EqualFold(a, domain) {
				return s, nil
			}
		}
	}
	return nil, nil
}

func DomainsFromSites(sites []Site) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range sites {
		add(s.Name + ".netlify.app")
		add(s.CustomDomain)
		for _, a := range s.DomainAliases {
			add(a)
		}
		if u, err := url.Parse(s.URL); err == nil {
			add(u.Hostname())
		}
		if u, err := url.Parse(s.SSLURL); err == nil {
			add(u.Hostname())
		}
	}
	return out
}
