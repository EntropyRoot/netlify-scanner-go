# netlify-scanner-go

> Maintained by **[EntropyRoot](https://github.com/EntropyRoot)**
> 🇮🇷 برای نسخه‌ی فارسی + توضیح هدف و ضد‌سانسور بودن: **[README.fa.md](README.fa.md)**

A scanner and recon orchestrator for assets fronted by the **Netlify** edge. Multi-signal classifier, OSINT corpus builder, slug brute force, JARM matcher, and a TUI to drive everything live.

> ⚠️ **Use only on assets you are authorized to test.** Defensive/recon tool.

---

## Features

- **Multi-signal classifier** — a host is flagged Netlify only when its cumulative score reaches 30, from independent signals (CNAME suffix, apex fallback A record, AS54113 membership, TLS SAN, headers, JARM).
- **`verify` stage** — every IP/SNI can be TLS-handshaked + HTTP-probed to confirm it really serves a Netlify cert. Eliminates seed-list noise.
- **IP allow-set builder (`discover`)** — merges seed IPs, live BGP expansion of AS54113, embedded SNI corpus resolution, and (optionally) an iterative aggressive harvest from seven OSINT sources.
- **OSINT harvest (`harvest`)** — pulls Netlify-fronted hostnames from crt.sh / certspotter / hackertarget / alienvault / rapiddns / subdomain.center / wayback.
- **Slug brute force (`slug`)** — wildcard-DNS-safe HTTPS HEAD probe with prefix/suffix mutation + wordlists.
- **JARM matcher (`jarm`)** — fingerprint hosts via tlsx, check against a known Netlify hash set, and learn new ones into a user cache file.
- **`iran` mode** — restricted-network workflow using only Go's standard library; no external tools required. See [README.fa.md](README.fa.md) for the long version in Persian.
- **`diff`, `replay`** — compare two JSONL outputs, or replay a recorded scan into the TUI offline.
- **Output formats** — `jsonl`, `ndjson`, `csv`, `sarif`, `text`.
- **Structured logging** — `slog` handler with `pretty` or `json` output, `--log-level=debug|info|warn|error`.
- **Live TUI** — five tabs (Hosts / IPs / Verified / Events / Stats), filtering, scroll, help overlay, and **runtime naabu rate control** (`+`/`-` and `]`/`[`).

---

## Install

```bash
go install github.com/EntropyRoot/netlify-scanner-go@latest
```

Or build from source:

```bash
git clone https://github.com/EntropyRoot/netlify-scanner-go
cd netlify-scanner-go
make build       # → ./bin/netlify-scanner-go
```

The first `scan`/`quick` run will fetch the ProjectDiscovery binaries (`subfinder`, `dnsx`, `httpx`, `naabu`, `nuclei`, `tlsx`, `asnmap`, `mapcidr`) into the local `bin/` cache. Run `netlify-scanner-go install` to pre-cache them.

---

## Quick start

```bash
# Full pipeline with TUI
netlify-scanner-go scan -t example.com

# One-shot aggressive: harvest + ASN + SNI + iterative loop + pipeline
netlify-scanner-go quick -t example.com -o results.jsonl

# Standalone fingerprint of one or more hosts (JARM auto-included if tlsx is installed)
netlify-scanner-go check app.example.com

# Verify a list of inherited IPs/SNIs — drop the noise BEFORE trusting it
netlify-scanner-go verify --ips inherited-ips.txt --snis sni.txt -o report.json

# Slug brute-force (wildcard-safe HTTP probe)
netlify-scanner-go slug --wordlist top-10k.txt --only-live -o live.txt
netlify-scanner-go slug --from-hosts hosts.txt --mutate -o slug.json

# JARM fingerprint learn / check
netlify-scanner-go jarm --learn --ips netlify-ips.txt        # populate user cache
netlify-scanner-go jarm --host app.netlify.com               # check against known

# Restricted-network mode (no external tools, stdlib only)
netlify-scanner-go iran --cidr 199.36.158.0/23 -o iran.json
```

---

## Subcommands

| command    | purpose                                                              |
| ---------- | -------------------------------------------------------------------- |
| `scan`     | Full pipeline against a target apex domain (with TUI)                |
| `quick`    | One-shot aggressive: harvest + ASN + SNI + iterative + pipeline      |
| `check`    | Standalone fingerprint of one or more hosts (JARM if tlsx available) |
| `verify`   | Cert/SAN + `x-nf-request-id` confirmation for IPs/SNIs               |
| `discover` | Build a Netlify IP allow-set (seed + ASN + SNI [+ harvest])          |
| `harvest`  | Pull Netlify hostnames from seven OSINT sources                      |
| `slug`     | `<slug>.netlify.app` brute-force (wildcard-safe HTTPS HEAD)          |
| `jarm`     | JARM fingerprint learn / check (uses tlsx)                           |
| `iran`     | Restricted-network workflow (stdlib only, see Persian README)        |
| `diff`     | Compare two JSONL outputs (added / removed / changed)                |
| `replay`   | Play back a recorded session into the TUI (no network)               |
| `sni`      | Print the embedded Netlify SNI seed corpus                           |
| `install`  | Install/update all required external tools                           |

---

## Scoring

A host is classified as Netlify when its cumulative score reaches **30**.

| signal                                | points |
| ------------------------------------- | -----: |
| `x-nf-request-id` (or any `x-nf-*`)   |    +60 |
| CNAME ends in a Netlify suffix        |    +50 |
| `A == 75.2.60.5` (apex fallback)      |    +50 |
| IP ∈ AS54113 allow-set                |    +30 |
| JARM matches a known Netlify hash     |    +25 |
| `Server: Netlify`                     |    +25 |
| TLS SAN matches a Netlify suffix      |    +20 |

Netlify suffixes: `.netlify.app.`, `.netlify.com.`, `.netlifyglobalcdn.com.`, `.nfshost.com.`.

---

## TUI keys

| key                  | action                            |
| -------------------- | --------------------------------- |
| `1`–`5`              | switch tab                        |
| `tab` / `shift+tab`  | cycle tabs                        |
| `/`                  | filter current tab (`esc` clears) |
| `j`/`k`  `↑`/`↓`     | scroll                            |
| `pgup` / `pgdown`    | half-page                         |
| `g` / `G`            | top / bottom                      |
| **`+` / `-`**        | **naabu rate ±100 pps (live)**    |
| **`]` / `[`**        | **naabu rate ±1000 pps (live)**   |
| `?`                  | toggle help                       |
| `q` / `ctrl+c`       | quit (cancels in-flight scan)     |

---

## Iran mode

`netlify-scanner-go iran` — designed for networks with heavy censorship/filtering. Pure Go, **no external binaries**. See [README.fa.md](README.fa.md) for the full description in Persian.

```bash
# Default: use embedded seed SNIs + IPs
netlify-scanner-go iran -o iran-report.json

# Add CIDR ranges (no need for BGP if blocked)
netlify-scanner-go iran --cidr 199.36.158.0/23 --cidr 75.2.60.0/24 -o iran.json

# Cap and tune
netlify-scanner-go iran \
  --cidrs ranges.txt --ips extras.txt \
  --workers 256 --timeout 3s --max-ips 50000 -o iran.json
```

Three-step flow: (1) probe seed SNIs to see which are reachable, (2) probe candidate IPs over TLS to harvest cert SANs, (3) re-probe harvested SANs from the local network. The report links **(SNI, IP)** pairs that BOTH respond.

---

## Roadmap

- [x] `verify` stage (cert/SAN + `x-nf-request-id`)
- [x] Iterative aggressive loop with `StrictSAN`
- [x] Slug brute force (HTTPS, wildcard-safe)
- [x] JARM fingerprint match (+25)
- [x] CNAME → `app.netlify.com/sites/<slug>` public-access check
- [x] Iran (restricted-network) mode
- [x] Naabu rate live-control from TUI
- [x] Output formats: jsonl / ndjson / csv / sarif / text
- [x] Structured `slog` logging (`--log-level`, `--log-format`)
- [x] Unit tests for classifier + slug + JARM
- [ ] Goreleaser config
- [ ] OTel / Prometheus progress streaming
- [ ] Cache layer for OSINT sources (`~/.cache/netlify-scanner-go/`)

---

## Credits

- **Author / maintainer:** [EntropyRoot](https://github.com/EntropyRoot)
- **Original inspiration:** [`IR-NETLIFY/NETLIFY-SCANNER`](https://github.com/IR-NETLIFY/NETLIFY-SCANNER)

## License

[MIT](LICENSE)
