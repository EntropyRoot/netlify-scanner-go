package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
	"github.com/ir-netlify/netlify-scanner-go/internal/output"
	"github.com/ir-netlify/netlify-scanner-go/internal/tools"
)

type Config struct {
	Target      string
	Tools       tools.Set
	NaabuPorts  string
	NucleiTags  string
	Concurrency int
	SkipNaabu   bool
	SkipNuclei  bool
	NetlifyIPs  map[string]struct{}
	OnEvent     EventFn
	OutputJSONL io.Writer       // legacy raw JSONL writer
	OutputW     output.Writer   // preferred: format-aware writer (jsonl/csv/sarif/text)
	Logger      *slog.Logger

	// NaabuRate is the rate (packets/sec) passed to naabu via -rate. It can
	// be updated live from the TUI; the value is re-read just before naabu
	// starts. 0 means "do not pass -rate" (use naabu default).
	NaabuRate *atomic.Int64
}

type EventKind string

const (
	EvStage   EventKind = "stage"
	EvFound   EventKind = "found"
	EvVerdict EventKind = "verdict"
	EvHTTPX   EventKind = "httpx"
	EvNaabu   EventKind = "naabu"
	EvNuclei  EventKind = "nuclei"
	EvLog     EventKind = "log"
	EvError   EventKind = "error"
)

type Event struct {
	Kind    EventKind
	Stage   string
	Message string
	Verdict *netlify.Verdict
}

type EventFn func(Event)

type Runner struct {
	cfg  Config
	emit EventFn
	log  *slog.Logger
}

func New(cfg Config) *Runner {
	if cfg.OnEvent == nil {
		cfg.OnEvent = func(Event) {}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	return &Runner{cfg: cfg, emit: cfg.OnEvent, log: cfg.Logger}
}

func (r *Runner) Run(ctx context.Context) error {
	r.stage("subfinder", "enumerating subdomains for "+r.cfg.Target)
	subs, err := r.subfinder(ctx)
	if err != nil {
		return fmt.Errorf("subfinder: %w", err)
	}
	for _, s := range subs {
		r.emit(Event{Kind: EvFound, Message: s})
	}
	if len(subs) == 0 {
		subs = []string{r.cfg.Target}
	}

	r.stage("dnsx", fmt.Sprintf("resolving %d hosts", len(subs)))
	resolved, err := r.dnsx(ctx, subs)
	if err != nil {
		return fmt.Errorf("dnsx: %w", err)
	}

	hits := r.classify(resolved)
	if len(hits) == 0 {
		r.emit(Event{Kind: EvLog, Message: "no Netlify-fronted hosts identified"})
		return nil
	}

	r.stage("httpx", fmt.Sprintf("HTTP probing %d hosts", len(hits)))
	if err := r.streamTool(ctx, "httpx", httpxArgs(), hits, EvHTTPX); err != nil {
		r.emit(Event{Kind: EvError, Message: "httpx: " + err.Error()})
	}

	g, gctx := errgroup.WithContext(ctx)
	if !r.cfg.SkipNaabu {
		g.Go(func() error {
			rate := int64(0)
			if r.cfg.NaabuRate != nil {
				rate = r.cfg.NaabuRate.Load()
			}
			r.stage("naabu", fmt.Sprintf("port scanning (rate=%d)", rate))
			return r.streamTool(gctx, "naabu", naabuArgs(r.cfg.NaabuPorts, rate), hits, EvNaabu)
		})
	}
	if !r.cfg.SkipNuclei {
		g.Go(func() error {
			r.stage("nuclei", "templated scans")
			return r.streamTool(gctx, "nuclei", nucleiArgs(r.cfg.NucleiTags), hits, EvNuclei)
		})
	}
	if err := g.Wait(); err != nil {
		r.emit(Event{Kind: EvError, Message: err.Error()})
	}

	r.stage("done", fmt.Sprintf("complete — %d Netlify hosts", len(hits)))
	return nil
}

func (r *Runner) classify(records []dnsxRecord) []string {
	hits := make([]string, 0, len(records))
	for _, rec := range records {
		v := netlify.Verdict{Host: rec.Host, CNAME: rec.CNAME, Addrs: rec.A}
		if rec.CNAME != "" {
			lc := strings.ToLower(rec.CNAME) + "."
			for _, suf := range netlify.CNAMESuffixes {
				if strings.HasSuffix(lc, suf) {
					v.Signals.CNAMEMatch = strings.TrimSuffix(suf, ".")
					v.Score += 50
					break
				}
			}
		}
		for _, a := range rec.A {
			if a == netlify.FallbackApexA {
				v.Signals.APEXFallback = true
				v.Score += 50
			}
			if _, ok := r.cfg.NetlifyIPs[a]; ok {
				v.Signals.ASNMatch = true
				v.Score += 30
			}
		}
		if v.Score >= 30 {
			v.IsNetlify = true
			hits = append(hits, rec.Host)
			r.emit(Event{Kind: EvVerdict, Verdict: &v})
			r.writeJSONL(v)
		}
	}
	return hits
}

func (r *Runner) stage(name, msg string) {
	r.emit(Event{Kind: EvStage, Stage: name, Message: msg})
	r.log.Info("stage", "stage", name, "msg", msg)
}

func (r *Runner) writeJSONL(v netlify.Verdict) {
	if r.cfg.OutputW != nil {
		_ = r.cfg.OutputW.Write(v)
		return
	}
	if r.cfg.OutputJSONL == nil {
		return
	}
	if b, err := json.Marshal(v); err == nil {
		_, _ = r.cfg.OutputJSONL.Write(append(b, '\n'))
	}
}

func (r *Runner) subfinder(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, r.cfg.Tools["subfinder"], "-silent", "-d", r.cfg.Target)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var subs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			subs = append(subs, s)
		}
	}
	return subs, nil
}

type dnsxRecord struct {
	Host  string
	A     []string
	CNAME string
}

func (r *Runner) dnsx(ctx context.Context, hosts []string) ([]dnsxRecord, error) {
	cmd := exec.CommandContext(ctx, r.cfg.Tools["dnsx"], "-silent", "-resp", "-a", "-cname", "-json")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		for _, h := range hosts {
			fmt.Fprintln(stdin, h)
		}
	}()
	var records []dnsxRecord
	dec := json.NewDecoder(stdout)
	for {
		var raw struct {
			Host  string   `json:"host"`
			A     []string `json:"a"`
			CNAME []string `json:"cname"`
		}
		if err := dec.Decode(&raw); err != nil {
			break
		}
		first := ""
		if len(raw.CNAME) > 0 {
			first = raw.CNAME[0]
		}
		records = append(records, dnsxRecord{Host: raw.Host, A: raw.A, CNAME: first})
	}
	_ = cmd.Wait()
	return records, nil
}

func (r *Runner) streamTool(ctx context.Context, name string, args, hosts []string, kind EventKind) error {
	bin := r.cfg.Tools[name]
	if bin == "" {
		return fmt.Errorf("missing binary: %s", name)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		for _, h := range hosts {
			fmt.Fprintln(stdin, h)
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<23)
		for sc.Scan() {
			r.emit(Event{Kind: kind, Stage: name, Message: sc.Text()})
		}
	}()
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if line := sc.Text(); line != "" {
				r.emit(Event{Kind: EvLog, Stage: name, Message: line})
			}
		}
	}()
	wg.Wait()
	return cmd.Wait()
}

func httpxArgs() []string {
	return []string{"-silent", "-status-code", "-title", "-tech-detect", "-server", "-favicon", "-jarm", "-tls-grab", "-json"}
}

func naabuArgs(ports string, rate int64) []string {
	if ports == "" {
		ports = "80,443,8443"
	}
	args := []string{"-silent", "-p", ports}
	if rate > 0 {
		args = append(args, "-rate", strconv.FormatInt(rate, 10))
	}
	return args
}

func nucleiArgs(tags string) []string {
	if tags == "" {
		tags = "cdn,exposure,tech"
	}
	return []string{"-silent", "-tags", tags, "-jsonl"}
}

