package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/ir-netlify/netlify-scanner-go/internal/diff"
	"github.com/ir-netlify/netlify-scanner-go/internal/discover"
	"github.com/ir-netlify/netlify-scanner-go/internal/iran"
	"github.com/ir-netlify/netlify-scanner-go/internal/jarm"
	"github.com/ir-netlify/netlify-scanner-go/internal/logging"
	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
	"github.com/ir-netlify/netlify-scanner-go/internal/output"
	"github.com/ir-netlify/netlify-scanner-go/internal/pipeline"
	"github.com/ir-netlify/netlify-scanner-go/internal/replay"
	"github.com/ir-netlify/netlify-scanner-go/internal/tools"
	"github.com/ir-netlify/netlify-scanner-go/internal/tui"
	"github.com/ir-netlify/netlify-scanner-go/internal/verify"
)

func Execute() error { return rootCmd.Execute() }

var globalFlags struct {
	logLevel  string
	logFormat string
}

var rootCmd = &cobra.Command{
	Use:   "netlify-scanner-go",
	Short: "Netlify edge fingerprinter & recon orchestrator",
}

func init() {
	rootCmd.AddCommand(scanCmd, checkCmd, installCmd, harvestCmd, discoverCmd, sniCmd, quickCmd, iranCmd, verifyCmd, diffCmd, replayCmd, slugCmd, jarmCmd)
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&globalFlags.logLevel, "log-level", "info", "log level: debug | info | warn | error")
	pf.StringVar(&globalFlags.logFormat, "log-format", "pretty", "log format: pretty | json")
	cobra.OnInitialize(func() {
		logging.Setup(logging.Options{
			Level:  globalFlags.logLevel,
			Format: globalFlags.logFormat,
		})
	})
}

// ───────────────── scan ─────────────────

var scanFlags struct {
	target     string
	ports      string
	tags       string
	output     string
	skipNaabu  bool
	skipNuclei bool
	noTUI      bool
	useASN     bool
	useSNI     bool
	useSeedIPs bool
	aggressive bool
	naabuRate  int64
	format     string
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run the full pipeline against a target apex domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanFlags.target == "" {
			return fmt.Errorf("--target is required")
		}
		ctx, cancel := signalCtx()
		defer cancel()

		bins, err := tools.NewResolver().EnsureAll(ctx, stderrLog)
		if err != nil {
			return err
		}
		for _, w := range bins.Healthcheck(ctx) {
			fmt.Fprintf(os.Stderr, "› ⚠ %s: %s\n   hint: %s\n", w.Tool, w.Reason, w.Hint)
		}

		ipset := buildIPSet(ctx, ipSetOpts{
			seedIPs: scanFlags.useSeedIPs,
			sni:     scanFlags.useSNI || scanFlags.aggressive,
			asn:     scanFlags.useASN || scanFlags.aggressive,
			agg:     scanFlags.aggressive,
			roots:   []string{"netlify.app", "netlify.com", "netlifyglobalcdn.com", "nfshost.com"},
			log:     stderrLog,
		})

		outW, closeOut, err := openFormatted(scanFlags.output, scanFlags.format)
		if err != nil {
			return err
		}
		defer closeOut()

		rate := new(atomic.Int64)
		rate.Store(scanFlags.naabuRate)
		cfg := pipeline.Config{
			Target:      scanFlags.target,
			Tools:       bins,
			NaabuPorts:  scanFlags.ports,
			NucleiTags:  scanFlags.tags,
			SkipNaabu:   scanFlags.skipNaabu,
			SkipNuclei:  scanFlags.skipNuclei,
			NetlifyIPs:  ipset.Snapshot(),
			OutputW:     outW,
			NaabuRate:   rate,
		}

		return runPipeline(ctx, cfg, scanFlags.noTUI, scanFlags.target, rate)
	},
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanFlags.target, "target", "t", "", "target apex domain")
	f.StringVar(&scanFlags.ports, "ports", "80,443,8443", "naabu ports")
	f.StringVar(&scanFlags.tags, "nuclei-tags", "cdn,exposure,tech", "nuclei template tags")
	f.StringVarP(&scanFlags.output, "output", "o", "", "JSONL verdict file")
	f.BoolVar(&scanFlags.skipNaabu, "skip-naabu", false, "skip port scan")
	f.BoolVar(&scanFlags.skipNuclei, "skip-nuclei", false, "skip nuclei")
	f.BoolVar(&scanFlags.noTUI, "no-tui", false, "plain stdout instead of TUI")
	f.BoolVar(&scanFlags.useASN, "asn", false, "expand AS54113 prefixes into the IP allow-set")
	f.BoolVar(&scanFlags.useSNI, "sni", true, "resolve embedded SNI corpus into the IP allow-set")
	f.BoolVar(&scanFlags.useSeedIPs, "seed-ips", true, "include the inherited seed IP list")
	f.BoolVar(&scanFlags.aggressive, "aggressive", false, "harvest from all sources + SAN reverse loop (slow but huge)")
	f.Int64Var(&scanFlags.naabuRate, "naabu-rate", 1000, "initial naabu packets/sec (adjust live in TUI with +/-)")
	f.StringVar(&scanFlags.format, "format", "jsonl", "output format: jsonl | ndjson | csv | sarif | text")
}

// ───────────────── quick ─────────────────

var quickFlags struct {
	target string
	output string
}

var quickCmd = &cobra.Command{
	Use:   "quick",
	Short: "One-shot aggressive scan: harvest + ASN + SNI + pipeline (TUI)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if quickFlags.target == "" {
			return fmt.Errorf("--target is required")
		}
		ctx, cancel := signalCtx()
		defer cancel()

		bins, err := tools.NewResolver().EnsureAll(ctx, stderrLog)
		if err != nil {
			return err
		}
		for _, w := range bins.Healthcheck(ctx) {
			fmt.Fprintf(os.Stderr, "› ⚠ %s: %s\n   hint: %s\n", w.Tool, w.Reason, w.Hint)
		}

		ipset := buildIPSet(ctx, ipSetOpts{
			seedIPs: true,
			sni:     true,
			asn:     true,
			agg:     true,
			roots:   []string{"netlify.app", "netlify.com", "netlifyglobalcdn.com"},
			log:     stderrLog,
		})

		outW, closeOut, err := openFormatted(quickFlags.output, "jsonl")
		if err != nil {
			return err
		}
		defer closeOut()

		rate := new(atomic.Int64)
		rate.Store(1000)
		cfg := pipeline.Config{
			Target:      quickFlags.target,
			Tools:       bins,
			NaabuPorts:  "80,443,8443",
			NucleiTags:  "cdn,exposure,tech",
			NetlifyIPs:  ipset.Snapshot(),
			OutputW:     outW,
			NaabuRate:   rate,
		}
		return runPipeline(ctx, cfg, false, quickFlags.target, rate)
	},
}

func init() {
	quickCmd.Flags().StringVarP(&quickFlags.target, "target", "t", "", "target apex domain")
	quickCmd.Flags().StringVarP(&quickFlags.output, "output", "o", "", "JSONL verdict file")
}

// ───────────────── check ─────────────────

var checkCmd = &cobra.Command{
	Use:   "check <host> [<host>...]",
	Short: "Standalone fingerprint of one or more hosts",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()
		c := netlify.NewClassifier(5 * time.Second)
		if tlsx := tools.NewResolver().Find("tlsx"); tlsx != "" {
			c.JARMProbe = func(pctx context.Context, host string) (string, bool) {
				res, err := jarm.ScanWithTLSX(pctx, tlsx, []string{host})
				if err != nil || len(res) == 0 {
					return "", false
				}
				return res[0].JARM, jarm.IsNetlify(res[0].JARM)
			}
		}
		for _, h := range args {
			v := c.Fingerprint(ctx, h)
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
		}
		return nil
	},
}

// ───────────────── install ─────────────────

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install or update all required external tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()
		_, err := tools.NewResolver().EnsureAll(ctx, stderrLog)
		return err
	},
}

// ───────────────── discover ─────────────────

var discoverFlags struct {
	asn        bool
	sni        bool
	seedIPs    bool
	aggressive bool
	output     string
	cap        int
	timeout    time.Duration
	workers    int
	roots      []string
}

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Build a Netlify IP allow-set from seed-IPs + ASN + SNI corpus",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()
		set := buildIPSet(ctx, ipSetOpts{
			seedIPs: discoverFlags.seedIPs,
			sni:     discoverFlags.sni,
			asn:     discoverFlags.asn,
			agg:     discoverFlags.aggressive,
			roots:   discoverFlags.roots,
			cap:     discoverFlags.cap,
			workers: discoverFlags.workers,
			timeout: discoverFlags.timeout,
			log:     stderrLog,
		})
		w := os.Stdout
		if discoverFlags.output != "" {
			f, err := os.Create(discoverFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		for _, ip := range set.Sorted() {
			fmt.Fprintln(w, ip)
		}
		fmt.Fprintf(os.Stderr, "› total: %d unique IPs\n", set.Len())
		return nil
	},
}

func init() {
	f := discoverCmd.Flags()
	f.BoolVar(&discoverFlags.asn, "asn", true, "expand AS54113 prefixes")
	f.BoolVar(&discoverFlags.sni, "sni", true, "resolve embedded SNI corpus")
	f.BoolVar(&discoverFlags.seedIPs, "seed-ips", true, "include inherited seed IPs")
	f.BoolVar(&discoverFlags.aggressive, "aggressive", false, "harvest all OSINT sources + reverse-SAN loop")
	f.StringVarP(&discoverFlags.output, "output", "o", "", "write IP list here (default: stdout)")
	f.IntVar(&discoverFlags.cap, "max-asn-ips", 200_000, "cap on IPs from ASN expansion")
	f.DurationVar(&discoverFlags.timeout, "timeout", 4*time.Second, "per-host DNS timeout")
	f.IntVar(&discoverFlags.workers, "workers", 128, "concurrency")
	f.StringSliceVar(&discoverFlags.roots, "root", []string{"netlify.app", "netlify.com", "netlifyglobalcdn.com", "nfshost.com"}, "harvest roots (--aggressive only)")
}

// ───────────────── harvest ─────────────────

var harvestFlags struct {
	roots  []string
	output string
}

var harvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "Pull Netlify-fronted hostnames from many OSINT sources (crt.sh, certspotter, hackertarget, alienvault, rapiddns, subdomain.center, wayback)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()
		stream := discover.HarvestAll(ctx, harvestFlags.roots, discover.DefaultSources, 6)
		seen, report := discover.DedupHosts(stream)
		w := os.Stdout
		if harvestFlags.output != "" {
			f, err := os.Create(harvestFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		for h := range seen {
			fmt.Fprintln(w, h)
		}
		for _, r := range report {
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "› %s: err=%v\n", r.Source, r.Err)
				continue
			}
			fmt.Fprintf(os.Stderr, "› %s: %d\n", r.Source, len(r.Hosts))
		}
		fmt.Fprintf(os.Stderr, "› total unique: %d\n", len(seen))
		return nil
	},
}

func init() {
	harvestCmd.Flags().StringSliceVar(&harvestFlags.roots, "root", []string{"netlify.app", "netlify.com", "netlifyglobalcdn.com", "nfshost.com"}, "roots to harvest")
	harvestCmd.Flags().StringVarP(&harvestFlags.output, "output", "o", "", "write hostnames here (default: stdout)")
}

// ───────────────── sni ─────────────────

var sniCmd = &cobra.Command{
	Use:   "sni",
	Short: "Print the embedded Netlify SNI seed corpus",
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, s := range netlify.SeedSNIs() {
			fmt.Println(s)
		}
		return nil
	},
}

// ───────────────── verify ─────────────────

var verifyFlags struct {
	ipsFile  string
	snisFile string
	output   string
	workers  int
	timeout  time.Duration
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify which IPs/SNIs actually serve Netlify (TLS SAN + x-nf-request-id)",
	Long: `verify takes a list of IPs and/or SNIs, opens TLS to each, and
inspects the peer cert + HTTP HEAD response. Each input is classified:

  confirmed    — cert SAN matches Netlify suffix, or x-nf-request-id seen
  not-netlify  — TCP/TLS/HTTP succeeded but no Netlify markers
  unreachable  — TCP/TLS/DNS failed

Use this to cut noise from inherited seed-IP lists before trusting them
in the scoring path.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()

		var ips, snis []string
		if verifyFlags.ipsFile != "" {
			f, err := os.Open(verifyFlags.ipsFile)
			if err != nil {
				return err
			}
			ips = readLines(f)
			f.Close()
		}
		if verifyFlags.snisFile != "" {
			f, err := os.Open(verifyFlags.snisFile)
			if err != nil {
				return err
			}
			snis = readLines(f)
			f.Close()
		}
		if len(ips) == 0 && len(snis) == 0 {
			return fmt.Errorf("at least one of --ips/--snis is required")
		}

		v := verify.New(verifyFlags.workers)
		if verifyFlags.timeout > 0 {
			v.DialTimeout = verifyFlags.timeout
		}
		v.OnIP = func(r verify.IPResult) {
			fmt.Fprintf(os.Stderr, "  %s ip  %s  san=%s nf=%s\n", statusGlyph(string(r.Status)), r.IP, r.CertSANMatch, r.NFRequestID)
		}
		v.OnSNI = func(r verify.SNIResult) {
			fmt.Fprintf(os.Stderr, "  %s sni %s  addrs=%d nf=%s\n", statusGlyph(string(r.Status)), r.Host, len(r.Addrs), r.NFRequestID)
		}

		ipResults := v.IPs(ctx, ips)
		sniResults := v.SNIs(ctx, snis)
		rep := verify.Summarize(ipResults, sniResults)
		rep.StartedAt = time.Now()
		rep.FinishedAt = time.Now()

		w := os.Stdout
		if verifyFlags.output != "" {
			f, err := os.Create(verifyFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if err := verify.WriteReport(w, rep); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n› ip:  confirmed=%d not-netlify=%d unreachable=%d\n",
			rep.IPCounts[verify.Confirmed], rep.IPCounts[verify.NotNetlify], rep.IPCounts[verify.Unreachable])
		fmt.Fprintf(os.Stderr, "› sni: confirmed=%d not-netlify=%d unreachable=%d\n",
			rep.SNICounts[verify.Confirmed], rep.SNICounts[verify.NotNetlify], rep.SNICounts[verify.Unreachable])
		return nil
	},
}

func statusGlyph(s string) string {
	switch s {
	case "confirmed", "open":
		return "✓"
	case "not-netlify", "filtered":
		return "✗"
	default:
		return "·"
	}
}

func init() {
	f := verifyCmd.Flags()
	f.StringVar(&verifyFlags.ipsFile, "ips", "", "file with IPs to verify (one per line)")
	f.StringVar(&verifyFlags.snisFile, "snis", "", "file with SNIs to verify (one per line)")
	f.StringVarP(&verifyFlags.output, "output", "o", "", "write JSON report here (default: stdout)")
	f.IntVar(&verifyFlags.workers, "workers", 64, "concurrent probes")
	f.DurationVar(&verifyFlags.timeout, "timeout", 4*time.Second, "dial timeout")
}

// ───────────────── diff ─────────────────

var diffFlags struct {
	output string
	asJSON bool
}

var diffCmd = &cobra.Command{
	Use:   "diff <old.jsonl> <new.jsonl>",
	Short: "Compare two JSONL scan outputs (added / removed / changed)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldM, err := diff.ReadJSONL(args[0])
		if err != nil {
			return err
		}
		newM, err := diff.ReadJSONL(args[1])
		if err != nil {
			return err
		}
		res := diff.Compute(oldM, newM)
		w := os.Stdout
		if diffFlags.output != "" {
			f, err := os.Create(diffFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if diffFlags.asJSON {
			return diff.WriteJSON(w, res)
		}
		diff.WriteText(w, res)
		return nil
	},
}

func init() {
	diffCmd.Flags().StringVarP(&diffFlags.output, "output", "o", "", "write here (default: stdout)")
	diffCmd.Flags().BoolVar(&diffFlags.asJSON, "json", false, "JSON instead of text")
}

// ───────────────── replay ─────────────────

var replayFlags struct {
	path  string
	speed float64
}

var replayCmd = &cobra.Command{
	Use:   "replay <session.ndjson>",
	Short: "Play back a recorded scan into the TUI (no network)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := replayFlags.path
		if path == "" && len(args) > 0 {
			path = args[0]
		}
		if path == "" {
			return fmt.Errorf("session path required")
		}
		ctx, cancel := signalCtx()
		defer cancel()
		ch := make(chan pipeline.Event, 1024)
		runCtx, runCancel := context.WithCancel(ctx)
		prog := tea.NewProgram(tui.New("replay:"+path, ch, runCancel), tea.WithAltScreen())
		go func() {
			defer close(ch)
			_ = replay.Play(runCtx, path, replayFlags.speed, func(ev pipeline.Event) {
				select {
				case ch <- ev:
				case <-runCtx.Done():
				}
			})
		}()
		_, err := prog.Run()
		return err
	},
}

func init() {
	replayCmd.Flags().StringVar(&replayFlags.path, "path", "", "session NDJSON path (or positional arg)")
	replayCmd.Flags().Float64Var(&replayFlags.speed, "speed", 1.0, "playback speed multiplier")
}

// ───────────────── jarm ─────────────────

var jarmFlags struct {
	learn   bool
	check   bool
	ipsFile string
	hosts   []string
	output  string
}

var jarmCmd = &cobra.Command{
	Use:   "jarm",
	Short: "JARM fingerprint helper (learn / check against known Netlify hashes)",
	Long: `jarm wraps the tlsx JARM probe.

Modes:

  --learn               Scan a list of hosts/IPs, record the JARM hashes
                        into the user cache file. Future scans will treat
                        those hashes as a Netlify signal (+25).
  --check  (default)    Scan hosts and report which ones match a known
                        Netlify JARM.

Inputs (any combination):
  --ips <file>          one host/IP per line
  --host <name>         single target (repeatable)
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()

		bins, err := tools.NewResolver().EnsureAll(ctx, stderrLog)
		if err != nil {
			return err
		}
		tlsx := bins["tlsx"]
		if tlsx == "" {
			return fmt.Errorf("tlsx binary not available")
		}

		var targets []string
		if jarmFlags.ipsFile != "" {
			f, err := os.Open(jarmFlags.ipsFile)
			if err != nil {
				return err
			}
			targets = readLines(f)
			f.Close()
		}
		targets = append(targets, jarmFlags.hosts...)
		targets = uniq(targets)
		if len(targets) == 0 {
			return fmt.Errorf("no targets: pass --ips and/or --host")
		}

		results, err := jarm.ScanWithTLSX(ctx, tlsx, targets)
		if err != nil {
			return err
		}

		w := os.Stdout
		if jarmFlags.output != "" {
			f, err := os.Create(jarmFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}

		switch {
		case jarmFlags.learn:
			hashes := make([]string, 0, len(results))
			for _, r := range results {
				hashes = append(hashes, r.JARM)
			}
			n, err := jarm.AppendLearned(hashes)
			if err != nil {
				return err
			}
			slog.Info("jarm learn complete", "scanned", len(results), "new_hashes", n)
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.JARM, r.Host, r.IP)
			}
		default:
			match, miss := 0, 0
			for _, r := range results {
				ok := jarm.IsNetlify(r.JARM)
				mark := "✗"
				if ok {
					mark = "✓"
					match++
				} else {
					miss++
				}
				fmt.Fprintf(w, "%s %s %-22s %s\n", mark, r.JARM, r.IP, r.Host)
			}
			slog.Info("jarm check complete", "match", match, "miss", miss, "total", len(results))
		}
		return nil
	},
}

func init() {
	f := jarmCmd.Flags()
	f.BoolVar(&jarmFlags.learn, "learn", false, "record observed hashes into the user cache for future runs")
	f.BoolVar(&jarmFlags.check, "check", true, "check observed hashes against the known Netlify set")
	f.StringVar(&jarmFlags.ipsFile, "ips", "", "file with hosts or IPs (one per line)")
	f.StringSliceVar(&jarmFlags.hosts, "host", nil, "single host or IP (repeatable)")
	f.StringVarP(&jarmFlags.output, "output", "o", "", "write here (default: stdout)")
}

// ───────────────── slug ─────────────────

var slugFlags struct {
	wordlist   string
	fromHosts  string
	mutate     bool
	output     string
	workers    int
	timeout    time.Duration
	onlyLive   bool
	extraSlugs []string
}

var slugCmd = &cobra.Command{
	Use:   "slug",
	Short: "Brute-force Netlify <slug>.netlify.app sites (HTTP-verified, wildcard-safe)",
	Long: `slug probes candidate "<slug>.netlify.app" hostnames over HTTPS
HEAD and decides which ones correspond to real sites.

Why not DNS / dnsx? *.netlify.app is a wildcard, so every slug — including
"definitely-not-a-real-site-12345" — resolves to the Netlify edge. The
edge itself returns HTTP 404 for unknown slugs (with x-nf-request-id
always set), which is the only reliable signal.

Sources (any combination):

  --wordlist <file>       one slug per line; "<slug>.netlify.app" is also
                          accepted and stripped
  --from-hosts <file>     extract slugs out of a list of hostnames (e.g.
                          the output of "harvest"); useful for then
                          permuting them with --mutate
  --slug <name>           repeatable single slug
  --mutate                expand each slug with prefix/suffix variants
                          (-dev, -staging, dev-, api-, …)

Examples:

  netlify-scanner-go slug --wordlist top-10k.txt -o live.txt
  netlify-scanner-go slug --from-hosts hosts.txt --mutate -o live.txt
  netlify-scanner-go slug --slug acme --mutate
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()

		candidates := append([]string{}, slugFlags.extraSlugs...)
		if slugFlags.wordlist != "" {
			ws, err := discover.LoadWordlist(slugFlags.wordlist)
			if err != nil {
				return err
			}
			candidates = append(candidates, ws...)
		}
		if slugFlags.fromHosts != "" {
			f, err := os.Open(slugFlags.fromHosts)
			if err != nil {
				return err
			}
			hosts := readLines(f)
			f.Close()
			extracted := discover.ExtractSiteSlugs(hosts)
			candidates = append(candidates, extracted...)
		}
		if slugFlags.mutate {
			candidates = discover.MutateSlugs(candidates)
		} else {
			candidates = uniq(candidates)
		}
		if len(candidates) == 0 {
			return fmt.Errorf("no slugs provided: use --wordlist / --from-hosts / --slug")
		}
		fmt.Fprintf(os.Stderr, "› probing %d slug(s) with %d workers, timeout=%s\n",
			len(candidates), slugFlags.workers, slugFlags.timeout)

		results := discover.ProbeSlugs(ctx, candidates, slugFlags.workers, slugFlags.timeout)

		var live, dead, errs int
		for _, r := range results {
			switch {
			case r.Live:
				live++
			case r.Err != "":
				errs++
			default:
				dead++
			}
		}

		w := os.Stdout
		if slugFlags.output != "" {
			f, err := os.Create(slugFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if slugFlags.onlyLive {
			for _, r := range results {
				if r.Live {
					fmt.Fprintln(w, r.Host)
				}
			}
		} else {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(struct {
				Total   int                          `json:"total"`
				Live    int                          `json:"live"`
				Dead    int                          `json:"dead"`
				Errors  int                          `json:"errors"`
				Results []discover.SlugProbeResult   `json:"results"`
			}{len(results), live, dead, errs, results})
		}
		fmt.Fprintf(os.Stderr, "› total=%d live=%d dead=%d err=%d\n",
			len(results), live, dead, errs)
		return nil
	},
}

func init() {
	f := slugCmd.Flags()
	f.StringVarP(&slugFlags.wordlist, "wordlist", "w", "", "wordlist file (one slug per line)")
	f.StringVar(&slugFlags.fromHosts, "from-hosts", "", "extract <slug> from a hostnames file (output of `harvest`)")
	f.StringSliceVar(&slugFlags.extraSlugs, "slug", nil, "single slug (repeatable)")
	f.BoolVarP(&slugFlags.mutate, "mutate", "m", false, "expand slugs with prefix/suffix variants")
	f.StringVarP(&slugFlags.output, "output", "o", "", "write here (default: stdout)")
	f.IntVar(&slugFlags.workers, "workers", 32, "concurrent probes")
	f.DurationVar(&slugFlags.timeout, "timeout", 5*time.Second, "per-probe HTTP timeout")
	f.BoolVar(&slugFlags.onlyLive, "only-live", false, "output only live hostnames (one per line)")
}

// ───────────────── iran ─────────────────

var iranFlags struct {
	output     string
	workers    int
	timeout    time.Duration
	ipsFile    string
	snisFile   string
	extraSNIs  []string
	extraIPs   []string
	cidrs      []string
	cidrsFile  string
	maxIPs     int
	maxPerCIDR int
}

var iranCmd = &cobra.Command{
	Use:   "iran",
	Short: "Restricted-network workflow (no external tools required)",
	Long: `Run a stdlib-only scan tailored for networks (e.g. inside Iran)
where many SNIs and IPs are blocked. Steps:

  1. Probe seed SNIs over TLS — which are reachable from THIS network?
  2. Probe candidate IPs on :443, read cert SANs — which Netlify edges are
     reachable from THIS network?
  3. Re-probe harvested SANs with SNI — which discovered hostnames are
     ALSO usable from THIS network?

The final JSON report links (SNI, IP) pairs that are usable from the
caller's network. No external binaries (subfinder, dnsx, naabu, nuclei)
are required — only Go's standard library.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalCtx()
		defer cancel()

		snis := netlify.SeedSNIs()
		if iranFlags.snisFile != "" {
			f, err := os.Open(iranFlags.snisFile)
			if err != nil {
				return err
			}
			snis = append(snis, readLines(f)...)
			f.Close()
		}
		snis = append(snis, iranFlags.extraSNIs...)
		snis = uniq(snis)

		ips := netlify.SeedIPs()
		if iranFlags.ipsFile != "" {
			f, err := os.Open(iranFlags.ipsFile)
			if err != nil {
				return err
			}
			ips = append(ips, readLines(f)...)
			f.Close()
		}
		ips = append(ips, iranFlags.extraIPs...)

		cidrs := append([]string{}, iranFlags.cidrs...)
		if iranFlags.cidrsFile != "" {
			f, err := os.Open(iranFlags.cidrsFile)
			if err != nil {
				return err
			}
			cidrs = append(cidrs, readLines(f)...)
			f.Close()
		}
		if len(cidrs) > 0 {
			set := discover.NewIPSet()
			nets := make([]*net.IPNet, 0, len(cidrs))
			for _, c := range cidrs {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				if !strings.Contains(c, "/") {
					if ip := net.ParseIP(c); ip != nil {
						ips = append(ips, ip.String())
					}
					continue
				}
				_, n, err := net.ParseCIDR(c)
				if err != nil {
					fmt.Fprintf(os.Stderr, "› cidr skip %q: %v\n", c, err)
					continue
				}
				nets = append(nets, n)
			}
			capPerCIDR := iranFlags.maxPerCIDR
			if capPerCIDR <= 0 {
				capPerCIDR = 65536
			}
			discover.ExpandPrefixes(nets, set, capPerCIDR*len(nets))
			ips = append(ips, set.Sorted()...)
			fmt.Fprintf(os.Stderr, "› expanded %d CIDR(s) → %d IPs\n", len(nets), set.Len())
		}

		ips = uniq(ips)
		if iranFlags.maxIPs > 0 && len(ips) > iranFlags.maxIPs {
			ips = ips[:iranFlags.maxIPs]
		}

		sc := iran.New(iranFlags.workers)
		if iranFlags.timeout > 0 {
			sc.DialTimeout = iranFlags.timeout
		}
		sc.OnLog = stderrLog
		var openSNI, openIP, blocked atomic.Int64
		sc.OnSNI = func(p iran.SNIProbe) {
			switch p.Status {
			case iran.Open:
				openSNI.Add(1)
				fmt.Fprintf(os.Stderr, "  ✓ sni  %s  addrs=%v\n", p.SNI, p.Addrs)
			case iran.Filtered:
				fmt.Fprintf(os.Stderr, "  ~ sni  %s  (TLS ok, no Netlify markers)\n", p.SNI)
			default:
				blocked.Add(1)
			}
		}
		sc.OnIP = func(p iran.IPProbe) {
			switch p.Status {
			case iran.Open:
				openIP.Add(1)
				fmt.Fprintf(os.Stderr, "  ✓ ip   %s  san=%s\n", p.IP, p.MatchSAN)
			case iran.Filtered:
				// Quieter for IPs since seed list is large.
			default:
				blocked.Add(1)
			}
		}

		rep := sc.Run(ctx, snis, ips)

		w := os.Stdout
		if iranFlags.output != "" {
			f, err := os.Create(iranFlags.output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if err := iran.WriteReport(w, rep); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n› open SNIs: %d   open IPs: %d   usable pairs: %d   harvested SANs: %d\n",
			len(rep.OpenSNIs), len(rep.OpenIPs), len(rep.Pairs), len(rep.HarvestedSNI))
		return nil
	},
}

func init() {
	f := iranCmd.Flags()
	f.StringVarP(&iranFlags.output, "output", "o", "", "write JSON report here (default: stdout)")
	f.IntVar(&iranFlags.workers, "workers", 32, "concurrent probes")
	f.DurationVar(&iranFlags.timeout, "timeout", 5*time.Second, "TLS/HTTP dial timeout")
	f.StringVar(&iranFlags.snisFile, "snis", "", "extra SNIs file (one per line)")
	f.StringVar(&iranFlags.ipsFile, "ips", "", "extra IPs file (one per line)")
	f.StringSliceVar(&iranFlags.extraSNIs, "sni", nil, "extra SNI (repeatable)")
	f.StringSliceVar(&iranFlags.extraIPs, "ip", nil, "extra IP (repeatable)")
	f.StringSliceVar(&iranFlags.cidrs, "cidr", nil, "CIDR range to expand and probe (repeatable, e.g. 199.36.158.0/23)")
	f.StringVar(&iranFlags.cidrsFile, "cidrs", "", "file with CIDR ranges (one per line)")
	f.IntVar(&iranFlags.maxPerCIDR, "max-per-cidr", 65536, "cap on IPs expanded PER CIDR (avoid /8 blow-up)")
	f.IntVar(&iranFlags.maxIPs, "max-ips", 0, "cap total IPs probed (0 = no cap)")
}

func readLines(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func uniq(ss []string) []string {
	seen := map[string]struct{}{}
	out := ss[:0]
	for _, s := range ss {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ───────────────── shared helpers ─────────────────

type ipSetOpts struct {
	seedIPs bool
	sni     bool
	asn     bool
	agg     bool
	roots   []string
	cap     int
	workers int
	timeout time.Duration
	log     func(string)
}

func buildIPSet(ctx context.Context, o ipSetOpts) *discover.IPSet {
	if o.cap == 0 {
		o.cap = 200_000
	}
	if o.workers == 0 {
		o.workers = 128
	}
	if o.timeout == 0 {
		o.timeout = 4 * time.Second
	}
	if o.log == nil {
		o.log = func(string) {}
	}
	set := discover.NewIPSet()

	if o.seedIPs {
		for _, ip := range netlify.SeedIPs() {
			set.Add(ip, "seed-list")
		}
		o.log(fmt.Sprintf("seed IPs   → %d", set.Len()))
	}

	if o.asn {
		o.log("fetching AS54113 prefixes (BGPView)…")
		if pfx, err := discover.ASNPrefixes(ctx, netlify.NetlifyASN); err == nil {
			before := set.Len()
			discover.ExpandPrefixes(pfx, set, o.cap)
			o.log(fmt.Sprintf("ASN expand → +%d", set.Len()-before))
		} else {
			o.log("ASN: " + err.Error())
		}
	}

	if o.agg {
		o.log("aggressive harvest + reverse-SAN loop…")
		ag := &discover.Aggressive{
			Roots:         o.roots,
			SeedHosts:     netlify.SeedSNIs(),
			Concurrency:   o.workers,
			IncludeASN:    false,
			MaxASNIPs:     o.cap,
			MaxRounds:     5,
			StrictSAN:     true,
			SlugMutations: true,
		}
		if res, err := ag.Run(ctx); err == nil {
			for _, ip := range res.IPs.Sorted() {
				set.Add(ip, "aggressive")
			}
			o.log(fmt.Sprintf("aggressive → total %d", set.Len()))
		} else {
			o.log("aggressive: " + err.Error())
		}
		return set
	}

	if o.sni {
		o.log(fmt.Sprintf("resolving %d SNI seeds…", len(netlify.SeedSNIs())))
		before := set.Len()
		rr := &discover.Resolver{R: net.DefaultResolver, Timeout: o.timeout, Workers: o.workers}
		_ = rr.Resolve(ctx, netlify.SeedSNIs(), set, nil)
		o.log(fmt.Sprintf("SNI resolve → +%d", set.Len()-before))
	}

	return set
}

func runPipeline(ctx context.Context, cfg pipeline.Config, noTUI bool, target string, naabuRate *atomic.Int64) error {
	if noTUI {
		cfg.OnEvent = func(ev pipeline.Event) {
			if ev.Kind == pipeline.EvVerdict && ev.Verdict != nil {
				fmt.Printf("[netlify] %-40s score=%d  %+v\n", ev.Verdict.Host, ev.Verdict.Score, ev.Verdict.Signals)
				return
			}
			if ev.Message != "" {
				fmt.Printf("[%s] %s\n", ev.Kind, ev.Message)
			}
		}
		return pipeline.New(cfg).Run(ctx)
	}

	ch := make(chan pipeline.Event, 1024)
	var dropped atomic.Int64
	cfg.OnEvent = func(ev pipeline.Event) {
		select {
		case ch <- ev:
		default:
			dropped.Add(1)
		}
	}
	runCtx, runCancel := context.WithCancel(ctx)
	prog := tea.NewProgram(tui.New(target, ch, runCancel).WithNaabuRate(naabuRate), tea.WithAltScreen())
	go func() {
		_ = pipeline.New(cfg).Run(runCtx)
		close(ch)
	}()
	_, err := prog.Run()
	if d := dropped.Load(); d > 0 {
		fmt.Fprintf(os.Stderr, "› dropped %d events under UI back-pressure\n", d)
	}
	return err
}

func openFormatted(path, format string) (output.Writer, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	fmtv, err := output.ParseFormat(format)
	if err != nil {
		return nil, func() {}, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	w := output.NewWriter(fmtv, f)
	return w, func() { _ = w.Close(); _ = f.Close() }, nil
}

// stderrLog bridges legacy callback-style log("foo") calls into slog. Tool
// installer / aggressive harvester / iran probe all call stderrLog; routing
// it through slog gives us level filtering and JSON output for free.
func stderrLog(s string) { slog.Info(s) }

func signalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}
