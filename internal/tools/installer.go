package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Tool struct {
	Name       string
	ImportPath string
	Purpose    string
}

var Required = []Tool{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "passive subdomain enumeration"},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "DNS resolution and CNAME chains"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", "HTTP probing and fingerprinting"},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "TCP port scanning"},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "templated vulnerability scanning"},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "TLS / SNI fingerprinting"},
	{"asnmap", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "ASN to CIDR mapping"},
	{"mapcidr", "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", "CIDR set arithmetic"},
}

type Resolver struct {
	cache map[string]string
}

func NewResolver() *Resolver { return &Resolver{cache: map[string]string{}} }

func (r *Resolver) Find(name string) string {
	if p, ok := r.cache[name]; ok {
		return p
	}
	p := find(name)
	if p != "" {
		r.cache[name] = p
	}
	return p
}

func find(name string) string {
	candidates := []string{name}
	if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".exe") {
		candidates = append([]string{name + ".exe"}, candidates...)
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
		for _, d := range goBinDirs() {
			cand := filepath.Join(d, c)
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand
			}
		}
	}
	return ""
}

func goBinDirs() []string {
	var dirs []string
	if v := os.Getenv("GOBIN"); v != "" {
		dirs = append(dirs, v)
	}
	if v := os.Getenv("GOPATH"); v != "" {
		for _, p := range filepath.SplitList(v) {
			dirs = append(dirs, filepath.Join(p, "bin"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	return dirs
}

func (r *Resolver) Install(ctx context.Context, t Tool, log func(string)) (string, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", errors.New("`go` toolchain not on PATH; install Go first")
	}
	log(fmt.Sprintf("installing %s …", t.Name))
	cmd := exec.CommandContext(ctx, "go", "install", t.ImportPath)
	cmd.Env = append(os.Environ(), "GO111MODULE=on", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("install %s: %w\n%s", t.Name, err, out)
	}
	delete(r.cache, t.Name)
	if p := r.Find(t.Name); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("%s installed but binary not found; check $GOBIN", t.Name)
}

type Set map[string]string

func (r *Resolver) EnsureAll(ctx context.Context, log func(string)) (Set, error) {
	out := Set{}
	for _, t := range Required {
		if p := r.Find(t.Name); p != "" {
			log(fmt.Sprintf("✓ %-9s %s", t.Name, p))
			out[t.Name] = p
			continue
		}
		p, err := r.Install(ctx, t, log)
		if err != nil {
			return out, err
		}
		log(fmt.Sprintf("✓ %-9s %s", t.Name, p))
		out[t.Name] = p
	}
	return out, nil
}

func (s Set) Need(names ...string) error {
	var missing []string
	for _, n := range names {
		if s[n] == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing tools: %s", strings.Join(missing, ", "))
	}
	return nil
}

type Warning struct {
	Tool   string
	Reason string
	Hint   string
}

func (s Set) Healthcheck(ctx context.Context) []Warning {
	var warns []Warning
	if bin := s["subfinder"]; bin != "" {
		if !subfinderHasKeys() {
			warns = append(warns, Warning{
				Tool:   "subfinder",
				Reason: "no provider API keys configured — passive enumeration will be very limited (~10% coverage)",
				Hint:   "edit ~/.config/subfinder/provider-config.yaml; see https://github.com/projectdiscovery/subfinder#post-install-instructions",
			})
		}
	}
	if bin := s["naabu"]; bin != "" {
		if !naabuRuntimeOK(ctx, bin) {
			warns = append(warns, Warning{
				Tool:   "naabu",
				Reason: "runtime check failed — likely missing libpcap/Npcap",
				Hint:   "linux: sudo apt install libpcap-dev   |   windows: install Npcap   |   or pass `--skip-naabu`",
			})
		}
	}
	return warns
}

func subfinderHasKeys() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	candidates := []string{
		filepath.Join(home, ".config", "subfinder", "provider-config.yaml"),
		filepath.Join(home, ".config", "subfinder", "provider-config.yml"),
	}
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err == nil && fi.Size() > 50 {
			return true
		}
	}
	return false
}

func naabuRuntimeOK(ctx context.Context, bin string) bool {
	cctx, cancel := contextWithTimeout(ctx, 5_000)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	low := strings.ToLower(string(out))
	if strings.Contains(low, "libpcap") && strings.Contains(low, "missing") {
		return false
	}
	return true
}

func contextWithTimeout(parent context.Context, ms int) (context.Context, context.CancelFunc) {
	type ctxImport = context.Context
	_ = ctxImport(nil)
	return context.WithTimeout(parent, time.Duration(ms)*time.Millisecond)
}
