# TrashRecon

TrashRecon is an automated reconnaissance framework for security researchers and penetration testers. It chains 17 tools across 10 phases to enumerate subdomains, extract DNS records, map ASN/CIDR ranges, scan ports, take screenshots, check for subdomain takeovers, crawl endpoints, search for vulnerability patterns, scan for exposed API keys, and optionally run nuclei — all from a single command inside Docker.

## Features

- **Subdomain Enumeration** — puredns (brute-force), subfinder, amass, assetfinder, waybackurls, and waymore run in parallel
- **Wildcard DNS Detection** — warns before enumeration if the target has wildcard DNS
- **HTTP Probing** — httpx filters live hosts by status code
- **DNS Record Extraction** — A records, CNAME records, and raw IPs via dnsx
- **ASN & CIDR Mapping** — maps discovered IPs to autonomous systems and CIDR ranges via asnmap
- **Port Scanning** — full port scan (0–65535) on unique IPs via smap
- **Screenshot Capture** — aquatone screenshots of all live hosts
- **Subdomain Takeover Check** — subzy checks CNAME dangling references
- **Endpoint Crawling** — katana crawls live hosts for endpoints (optional, interactive)
- **Vulnerability Pattern Search** — gf matches 14 patterns (XSS, SQLi, SSRF, SSTI, LFI, RCE, IDOR, etc.)
- **API Key Scanning** — secretx scans endpoints for exposed keys (optional, interactive)
- **Nuclei Scanning** — nuclei vulnerability scanner against live hosts (optional, interactive)
- **Colored Terminal Output** — clear, color-coded status messages for every phase
- **Scan Logging** — full log with timestamps saved to each scan folder (`trashrecon.log`)
- **Structured JSON Output** — `results.json` with all findings, consumable by other tools
- **Resume Support** — re-run against the same domain and completed steps are skipped automatically

## Phase Flow

```
Phase 1  · Subdomain Enumeration       (puredns + 5 passive tools in parallel)
Phase 2  · DNS Record Extraction        (A, CNAME, IPs via dnsx)
Phase 3  · ASN & CIDR Enumeration       (asnmap)
Phase 4  · Port Scanning                (smap, all ports)
Phase 5  · Screenshots                  (aquatone + chromium)
Phase 6  · Subdomain Takeover Check     (subzy — all resolved subdomains)
Phase 7  · Endpoint Crawling            (katana — interactive, can skip)
Phase 8  · GF Pattern Enumeration       (14 patterns — archived URLs + crawled endpoints)
  Phase 9  · API Key Scanning           (secretx — interactive, only if Phase 7 ran)
Phase 10 · Nuclei Vulnerability Scan    (nuclei — interactive, independent)
```

## Output Files

All results are saved to `~/TrashRecon/<domain>/` (bind-mounted in Docker):

| File | Description |
|------|-------------|
| `final_subdomains.txt` | Deduplicated subdomains from all sources |
| `workingdomains.txt` | Live hosts (HTTP 200/3xx) |
| `a_records.txt` | A records with responses |
| `cname.txt` | CNAME records |
| `IPs.txt` | Unique IPs |
| `asn_info.json` | ASN data per IP (JSONL) |
| `cidr_ranges.txt` | Unique CIDR ranges |
| `port_scan.json` | Full port scan results |
| `aquatone/` | Screenshots and HTML report |
| `subdomains_takeover.txt` | Subdomain takeover results |
| `endpoints.txt` | Crawled endpoints |
| `GF/` | Per-pattern GF results (xss.txt, sqli.txt, etc.) |
| `api.txt` | Exposed API keys |
| `nuclei.jsonl` | Nuclei findings (JSONL) |
| `results.json` | Structured summary of everything |
| `trashrecon.log` | Timestamped scan log |

## Installation

### Docker (recommended)

```bash
docker pull 0xs0m/trashrecon:latest
```

```bash
docker run --rm -v ~/TrashRecon:/root/TrashRecon 0xs0m/trashrecon example.com
```

Or run interactively (prompts for domain):

```bash
docker run -it --rm -v ~/TrashRecon:/root/TrashRecon 0xs0m/trashrecon
```

### Build from source

```bash
git clone https://github.com/Somchandra17/TrashRecon.git
cd TrashRecon
docker buildx build -t trashrecon .
docker run --rm -v ~/TrashRecon:/root/TrashRecon trashrecon example.com
```

## Usage

```
trashrecon [domain] [options]

positional:
  domain                 target domain (prompted if omitted on a TTY)

options:
  -y, --yes,             auto-proceed the optional phases (7, 9, 10)
      --non-interactive  without prompting — required for headless runs
  -o, --output DIR       output base directory (default: ~/TrashRecon)
  --skip-phases LIST     comma-separated phase numbers to skip, e.g. 4,5,10
  --wordlist PATH        subdomain brute-force wordlist (default: bundled list)
  --version              print version and exit
  -h, --help             show help and exit
```

Headless run (no TTY) — pass `--yes` so the interactive phases still execute:

```bash
docker run --rm -v ~/TrashRecon:/root/TrashRecon 0xs0m/trashrecon example.com --yes
```

> **Note:** `--skip-phases` is best-effort. Phases run in sequence and later
> phases consume earlier output (e.g. Phase 2 needs Phase 1's live hosts), so
> skipping an early phase may leave downstream phases with nothing to process.

## Updating Wordlists & Resolvers

The bundled `resolvers.txt` and `subdomains-top1million-110000.txt` are baked into the Docker image at build time. To refresh them before rebuilding:

```bash
./update-lists.sh
docker buildx build -t trashrecon .
```

The script pulls the latest versions from [trickest/resolvers](https://github.com/trickest/resolvers) and [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists). If a download fails, the existing file is kept.

## Tools

TrashRecon bundles these tools inside the Docker image:

| Tool | Purpose |
|------|---------|
| [puredns](https://github.com/d3mondev/puredns) | DNS brute-force with massdns |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |
| [amass](https://github.com/owasp-amass/amass) | Subdomain enumeration (v3) |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Asset discovery |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback Machine URL extraction |
| [waymore](https://github.com/xnl-h4ck3r/waymore) | Extended archive URL collection |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing and filtering |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS record extraction |
| [asnmap](https://github.com/projectdiscovery/asnmap) | IP to ASN/CIDR mapping |
| [smap](https://github.com/s0md3v/Smap) | Shodan-backed port scanning |
| [aquatone](https://github.com/Abhinandan-Khurana/aquatone) | Screenshot capture |
| [subzy](https://github.com/PentestPad/subzy) | Subdomain takeover detection |
| [katana](https://github.com/projectdiscovery/katana) | Endpoint crawling |
| [gf](https://github.com/tomnomnom/gf) + [patterns](https://github.com/1ndianl33t/Gf-Patterns) | Vulnerability pattern matching |
| [secretx](https://github.com/Somchandra17/secretx) | API key scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning |
| [massdns](https://github.com/blechschmidt/massdns) | High-performance DNS resolver |

## License

MIT — see [LICENSE](LICENSE).
