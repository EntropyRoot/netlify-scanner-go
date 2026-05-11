// Package jarm wraps tlsx for JARM fingerprinting and exposes a small
// hash-set against which scan results can be matched.
package jarm

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed netlify-jarm.txt
var embeddedRaw string

// Boost is the score increment added to a verdict whose JARM matches a known
// Netlify edge fingerprint.
const Boost = 25

// userCachePath returns the writable JARM hash file in the user cache dir.
// Hashes learned via `jarm --learn` are appended here so the in-memory set
// grows across runs.
func userCachePath() string {
	if v := os.Getenv("NETLIFY_SCANNER_CACHE"); v != "" {
		return filepath.Join(v, "jarm-netlify.txt")
	}
	c, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(c, "netlify-scanner-go", "jarm-netlify.txt")
}

var (
	loadOnce sync.Once
	known    map[string]struct{}
)

func ensureLoaded() {
	loadOnce.Do(func() {
		known = parseHashes(embeddedRaw)
		if p := userCachePath(); p != "" {
			if b, err := os.ReadFile(p); err == nil {
				for h := range parseHashes(string(b)) {
					known[h] = struct{}{}
				}
			}
		}
	})
}

func parseHashes(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out[strings.ToLower(s)] = struct{}{}
	}
	return out
}

// KnownNetlifyHashes returns a copy of the loaded JARM hash set.
func KnownNetlifyHashes() map[string]struct{} {
	ensureLoaded()
	out := make(map[string]struct{}, len(known))
	for k := range known {
		out[k] = struct{}{}
	}
	return out
}

// IsNetlify reports whether the given JARM hash is in the known set.
func IsNetlify(hash string) bool {
	ensureLoaded()
	_, ok := known[strings.ToLower(strings.TrimSpace(hash))]
	return ok
}

// Result is one tlsx output row.
type Result struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	JARM string `json:"hash"`
}

// ScanWithTLSX shells out to `tlsx -jarm -json` and parses the stream.
func ScanWithTLSX(ctx context.Context, tlsxBin string, hosts []string) ([]Result, error) {
	if tlsxBin == "" {
		return nil, fmt.Errorf("tlsx binary not provided")
	}
	cmd := exec.CommandContext(ctx, tlsxBin, "-silent", "-jarm", "-json")
	cmd.Stdin = strings.NewReader(strings.Join(hosts, "\n"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var results []Result
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var raw struct {
			Host string `json:"host"`
			IP   string `json:"ip"`
			JARM string `json:"jarm_hash"`
		}
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		if raw.JARM != "" {
			results = append(results, Result{Host: raw.Host, IP: raw.IP, JARM: raw.JARM})
		}
	}
	_ = cmd.Wait()
	return results, nil
}

// AppendLearned writes new (deduped) hashes to the user cache file and
// updates the in-memory set.
func AppendLearned(hashes []string) (int, error) {
	ensureLoaded()
	path := userCachePath()
	if path == "" {
		return 0, fmt.Errorf("no cache dir available")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	added := 0
	for _, h := range hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := known[h]; ok {
			continue
		}
		known[h] = struct{}{}
		if _, err := fmt.Fprintln(f, h); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
