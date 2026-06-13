import sys
import os
import argparse
import subprocess
import threading
import time
import re
import random
import shlex
import shutil
import string
import json
import signal
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Shell-quote helper for interpolating paths/values into shell=True commands.
sq = shlex.quote

__version__ = "1.1.0"

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BANNER_PATH = os.path.join(SCRIPT_DIR, "banner.txt")
WORDLIST_PATH = os.path.expanduser("~/app/subdomains-top1million-110000.txt")

DEFAULT_OUTPUT_DIR = os.path.expanduser("~/TrashRecon")
TOTAL_PHASES = 10

DEFAULT_TIMEOUT = 3600

TOOL_TIMEOUTS = {
    'puredns': 2400,
    'subfinder': 900,
    'amass': 900,
    'assetfinder': 600,
    'waybackurls': 900,
    'waymore': 1800,
    'httpx': 1800,
    'dnsx': 900,
    'asnmap': 600,
    'smap': 7200,
    'aquatone': 2400,
    'subzy': 900,
    'katana': 7200,
    'secretx': 7200,
    'nuclei': 14400,
}

# External CLI binaries each phase invokes, used for the startup preflight.
# Phase 9's secretx runs as `python3 secretx.py` (not a PATH binary) and fails
# gracefully via run_tool, so it is intentionally omitted here.
PHASE_TOOLS = {
    1: ['puredns', 'subfinder', 'amass', 'assetfinder', 'waybackurls', 'waymore', 'httpx', 'dnsx'],
    2: ['dnsx'],
    3: ['asnmap'],
    4: ['smap'],
    5: ['aquatone', 'chromium'],
    6: ['subzy'],
    7: ['katana'],
    8: ['gf'],
    10: ['nuclei'],
}

done = threading.Event()
_start_time = 0

# Parsed CLI arguments (argparse.Namespace), set in main().
ARGS = None

# Serializes all console + log writes so parallel tools and the spinner
# never interleave or clobber each other's lines.
_print_lock = threading.Lock()

# Set while an interactive prompt is awaiting input; pauses the spinner
# so it doesn't overwrite the prompt line.
_prompt_active = threading.Event()

# =============================================================================
# Colors
# =============================================================================

class C:
    RESET = '\033[0m'
    BOLD  = '\033[1m'
    DIM   = '\033[2m'
    W     = '\033[37m'
    R     = '\033[31m'
    G     = '\033[32m'
    Y     = '\033[33m'
    GR    = '\033[90m'


def _disable_colors():
    """Blank every color constant so all C.* references emit plain text."""
    for k in vars(C):
        if not k.startswith('__'):
            setattr(C, k, '')

# =============================================================================
# Logging — dual output to console (colored) and log file (plain)
# =============================================================================

_log_file = None
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def setup_logging(domain_path):
    global _log_file
    path = os.path.join(domain_path, 'trashrecon.log')
    _log_file = open(path, 'a')
    _log_raw(f"{'='*60}")
    _log_raw(f"TrashRecon scan started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    _log_raw(f"{'='*60}")


def _log_raw(msg):
    """Write to log file only (ANSI-stripped)."""
    if _log_file:
        clean = _ANSI_RE.sub('', str(msg))
        with _print_lock:
            _log_file.write(f"[{time.strftime('%H:%M:%S')}] {clean}\n")
            _log_file.flush()


def log(msg=''):
    """Print to console and write to log file."""
    with _print_lock:
        # Wipe any leftover spinner glyph on the current terminal line.
        if sys.stdout.isatty():
            sys.stdout.write('\r\033[K')
        print(msg)
        if _log_file:
            clean = _ANSI_RE.sub('', str(msg))
            _log_file.write(f"[{time.strftime('%H:%M:%S')}] {clean}\n")
            _log_file.flush()

# =============================================================================
# Output helpers
# =============================================================================

def print_phase(num, title):
    log(f"\n  {C.W}{C.BOLD}[phase {num}]{C.RESET} {C.W}{title}{C.RESET}")


def print_success(msg):
    log(f"  {C.G}[+]{C.RESET} {msg}")


def print_error(msg):
    log(f"  {C.R}[!]{C.RESET} {msg}")


def print_warning(msg):
    log(f"  {C.Y}[!]{C.RESET} {msg}")


def print_info(msg):
    log(f"  {C.GR}[*]{C.RESET} {msg}")


def print_running(msg):
    log(f"  {C.GR}[>]{C.RESET} {msg}")


def print_skip(label):
    log(f"  {C.GR}[-] skipping {label}{C.RESET}")


def print_question(msg):
    log(f"\n  {C.W}[?]{C.RESET} {msg}")

# =============================================================================
# Core utilities
# =============================================================================

def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def in_scope(host, domain):
    """True if host is the domain itself or a subdomain of it. Boundary-aware,
    so 'example.com.evil.net' and 'notexample.com' are correctly rejected."""
    host = host.strip().lower().rstrip('.')
    domain = domain.strip().lower().rstrip('.')
    return host == domain or host.endswith('.' + domain)


def safe_input(prompt):
    # Pause the spinner and clear its line so it can't overwrite the prompt.
    _prompt_active.set()
    try:
        if sys.stdout.isatty():
            with _print_lock:
                sys.stdout.write('\r\033[K')
                sys.stdout.flush()
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ''
    finally:
        _prompt_active.clear()


def confirm(prompt):
    """Yes/no gate for optional phases. Auto-yes with --yes; in a
    non-interactive session with no --yes, default to no."""
    if ARGS is not None and ARGS.yes:
        return True
    if not sys.stdin.isatty():
        return False
    return safe_input(prompt).lower() == 'yes'


def run_command(command, cwd=None, timeout=DEFAULT_TIMEOUT):
    _log_raw(f"CMD: {command[:200]}")
    try:
        process = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, start_new_session=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        if stdout:
            output = stdout.decode(errors='replace').strip()
            if output:
                _log_raw(output[:5000])
        if process.returncode != 0:
            err = stderr.decode(errors='replace').strip()
            if err:
                print_error(err[:500])
            return False
        return True
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        process.communicate()
        print_error(f"Timed out after {timeout}s: {command[:80]}")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False


def file_ready(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


def count_lines(filepath):
    try:
        with open(filepath, 'r') as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='replace') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def extract_hostnames(input_file, output_file, filter_domain=None):
    """Extract unique hostnames from URLs/domains using urlparse."""
    hostnames = set()
    try:
        with open(input_file, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not line.startswith(('http://', 'https://')):
                    line = 'http://' + line
                try:
                    hostname = urlparse(line).hostname
                    if not hostname:
                        continue
                    hostname = hostname.lower()
                    if filter_domain is None or in_scope(hostname, filter_domain):
                        hostnames.add(hostname)
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    with open(output_file, 'w') as f:
        if hostnames:
            f.write('\n'.join(sorted(hostnames)) + '\n')
    return len(hostnames)


def check_wildcard_dns(domain):
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
    test = f"{random_sub}.{domain}"
    try:
        result = subprocess.run(
            f"echo {sq(test)} | dnsx -silent -nc",
            shell=True, capture_output=True, timeout=30, text=True
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def merge_files(input_files, output_file):
    lines = set()
    for path in input_files:
        try:
            with open(path, 'r', errors='replace') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        lines.add(stripped)
        except FileNotFoundError:
            continue
    with open(output_file, 'w') as f:
        if lines:
            f.write('\n'.join(sorted(lines)) + '\n')
    return len(lines)


def run_tool(name, command, cwd, output_file=None, timeout=DEFAULT_TIMEOUT):
    if output_file and file_ready(output_file):
        count = count_lines(output_file)
        print_info(f"Skipping {name} ({count} lines already exist)")
        return True

    print_running(f"Running {name}...")
    success = run_command(command, cwd=cwd, timeout=timeout)

    if output_file:
        n = count_lines(output_file)
        if success:
            print_success(f"{name}: {n} results")
        else:
            print_error(f"{name}: {n} results (errors)")
    else:
        if success:
            print_success(f"{name} done")
        else:
            print_error(f"{name} completed with errors")
    return success


def check_dependencies(skip):
    """Return the sorted list of CLI tools missing from PATH, considering only
    the phases that will actually run (i.e. not in `skip`)."""
    required = set()
    for phase, tools in PHASE_TOOLS.items():
        if phase not in skip:
            required.update(tools)
    return sorted(t for t in required if shutil.which(t) is None)


def create_domain_folder(domain):
    base = ARGS.output if ARGS is not None else DEFAULT_OUTPUT_DIR
    domain_path = os.path.join(os.path.expanduser(base), domain)
    os.makedirs(domain_path, exist_ok=True)
    return domain_path


def parse_asn_output(json_file, cidr_file):
    """Parse asnmap JSONL output and extract unique CIDR ranges."""
    cidrs = set()
    asns = set()
    try:
        with open(json_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    as_num = data.get('as_number', '')
                    if as_num:
                        asns.add(as_num)
                    for cidr in data.get('as_range', []):
                        cidrs.add(cidr)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    with open(cidr_file, 'w') as f:
        if cidrs:
            f.write('\n'.join(sorted(cidrs)) + '\n')
    return len(asns), len(cidrs)

# =============================================================================
# Phases 1-10
# =============================================================================

def phase_one(domain_path, domain):
    print_phase(1, "Subdomain Enumeration")
    j = lambda f: os.path.join(domain_path, f)

    print_running("Checking for wildcard DNS...")
    if check_wildcard_dns(domain):
        print_warning(f"Wildcard DNS detected for {domain}!")
        print_warning("Results may contain false positives.")
    else:
        print_success("No wildcard DNS detected.")

    run_tool('puredns',
             f"puredns bruteforce {sq(WORDLIST_PATH)} {sq(domain)} > {sq(j('puredns.txt'))}",
             cwd=domain_path, output_file=j('puredns.txt'),
             timeout=TOOL_TIMEOUTS['puredns'])

    passive_tools = {
        'subfinder':   (f"subfinder -nc -silent -d {sq(domain)} > {sq(j('subfinder.txt'))}",
                        j('subfinder.txt')),
        'amass':       (f"amass enum -passive -nocolor -d {sq(domain)} > {sq(j('amass.txt'))}",
                        j('amass.txt')),
        'assetfinder': (f"assetfinder -subs-only {sq(domain)} > {sq(j('assetfinder.txt'))}",
                        j('assetfinder.txt')),
        'waybackurls': (f"waybackurls {sq(domain)} > {sq(j('wayback.txt'))}",
                        j('wayback.txt')),
        'waymore':     (f"waymore -i {sq(domain)} -mode U -oU {sq(j('waymore.txt'))}",
                        j('waymore.txt')),
    }

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for name, (cmd, outfile) in passive_tools.items():
            future = executor.submit(
                run_tool, name, cmd, domain_path, outfile,
                TOOL_TIMEOUTS.get(name, DEFAULT_TIMEOUT)
            )
            futures[future] = name
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
            except Exception as e:
                print_error(f"{name} crashed: {e}")

    print_running("Merging and deduplicating results...")
    merge_files([j('wayback.txt'), j('waymore.txt')], j('merged_way.txt'))
    way_count = extract_hostnames(j('merged_way.txt'), j('way_domains.txt'),
                                  filter_domain=domain)
    print_success(f"{way_count} domains extracted from archived URLs")

    all_sources = [
        j('puredns.txt'), j('subfinder.txt'), j('amass.txt'),
        j('assetfinder.txt'), j('way_domains.txt')
    ]
    total = merge_files(all_sources, j('raw.txt'))
    print_success(f"{total} unique subdomains from all sources")

    try:
        with open(j('raw.txt'), 'r') as f:
            filtered = sorted({h for h in (l.strip().lower() for l in f)
                               if h and in_scope(h, domain)})
        with open(j('final_subdomains.txt'), 'w') as f:
            if filtered:
                f.write('\n'.join(filtered) + '\n')
        print_success(f"{len(filtered)} subdomains match {domain}")
    except FileNotFoundError:
        open(j('final_subdomains.txt'), 'w').close()

    print_running("Probing live hosts with httpx...")
    run_command(
        f"cat {sq(j('final_subdomains.txt'))} | httpx -nc -silent -mc 200,301,302,307,308 "
        f"> {sq(j('httpx_raw.txt'))}",
        cwd=domain_path, timeout=TOOL_TIMEOUTS['httpx']
    )
    live = extract_hostnames(j('httpx_raw.txt'), j('workingdomains.txt'))
    print_success(f"Phase 1 complete: {C.BOLD}{live}{C.RESET} live hosts")


def phase_two(domain_path):
    print_phase(2, "DNS Record Extraction")
    j = lambda f: os.path.join(domain_path, f)
    w = j('workingdomains.txt')
    t = TOOL_TIMEOUTS['dnsx']

    run_tool('dnsx (A records)',
             f"cat {sq(w)} | dnsx -a -resp -nc | sort -u > {sq(j('a_records.txt'))}",
             cwd=domain_path, output_file=j('a_records.txt'), timeout=t)
    run_tool('dnsx (CNAME)',
             f"cat {sq(w)} | dnsx -silent -cname -resp -nc > {sq(j('cname.txt'))}",
             cwd=domain_path, output_file=j('cname.txt'), timeout=t)
    run_tool('dnsx (IPs)',
             f"cat {sq(w)} | dnsx -a -ro -nc | sort -u > {sq(j('IPs.txt'))}",
             cwd=domain_path, output_file=j('IPs.txt'), timeout=t)

    print_success(f"Phase 2 complete: {C.BOLD}{count_lines(j('IPs.txt'))}{C.RESET} unique IPs")


def phase_three(domain_path):
    print_phase(3, "ASN & CIDR Enumeration")
    j = lambda f: os.path.join(domain_path, f)

    run_tool('asnmap',
             f"cat {sq(j('IPs.txt'))} | asnmap -silent -json > {sq(j('asn_info.json'))}",
             cwd=domain_path, output_file=j('asn_info.json'),
             timeout=TOOL_TIMEOUTS['asnmap'])

    asn_count, cidr_count = parse_asn_output(j('asn_info.json'), j('cidr_ranges.txt'))
    print_success(f"Phase 3 complete: {C.BOLD}{asn_count}{C.RESET} ASNs, "
                  f"{C.BOLD}{cidr_count}{C.RESET} CIDR ranges")


def phase_four(domain_path):
    print_phase(4, "Port Scanning")
    j = lambda f: os.path.join(domain_path, f)

    ip_count = count_lines(j('IPs.txt'))
    print_info(f"Scanning {ip_count} unique IPs (all ports)")

    run_tool('smap',
             f"smap -Pn -p0-65535 -iL {sq(j('IPs.txt'))} -oJ {sq(j('port_scan.json'))}",
             cwd=domain_path, output_file=j('port_scan.json'),
             timeout=TOOL_TIMEOUTS['smap'])
    print_success("Phase 4 complete")


def phase_five(domain_path):
    print_phase(5, "Screenshots")
    j = lambda f: os.path.join(domain_path, f)
    aquatone_dir = j('aquatone')
    report = os.path.join(aquatone_dir, 'aquatone_report.html')

    if os.path.isfile(report):
        print_info("Skipping aquatone (report already exists)")
        print_success("Phase 5 complete")
        return

    run_tool('aquatone',
             f"cat {sq(j('httpx_raw.txt'))} | aquatone -chrome-path /usr/bin/chromium "
             f"-scan-timeout 1000 -screenshot-timeout 30000 "
             f"-out {sq(aquatone_dir)}",
             cwd=domain_path, timeout=TOOL_TIMEOUTS['aquatone'])
    print_success("Phase 5 complete")


def phase_six(domain_path):
    print_phase(6, "Subdomain Takeover Check")
    j = lambda f: os.path.join(domain_path, f)

    # Scan all resolved subdomains, not just live hosts — takeover candidates
    # are usually dangling hosts that httpx's status filter would have dropped.
    run_tool('subzy',
             f"subzy run --targets {sq(j('final_subdomains.txt'))} > {sq(j('subdomains_takeover.txt'))}",
             cwd=domain_path, output_file=j('subdomains_takeover.txt'),
             timeout=TOOL_TIMEOUTS['subzy'])
    print_success("Phase 6 complete")


def phase_seven(domain_path, domain):
    j = lambda f: os.path.join(domain_path, f)
    working_count = count_lines(j('workingdomains.txt'))

    print_question(f"Phase 7 will crawl endpoints on {working_count} live hosts.")
    log("      This can be time-consuming on large surfaces.")
    if not confirm("      proceed? (yes/no): "):
        print_skip("Phase 7")
        return False

    print_phase(7, "Endpoint Crawling")
    run_tool('katana',
             f"katana -u {sq(j('workingdomains.txt'))} -d 5 -jsl -jc -o {sq(j('endpoints.txt'))}",
             cwd=domain_path, output_file=j('endpoints.txt'),
             timeout=TOOL_TIMEOUTS['katana'])

    print_success(f"Phase 7 complete: {C.BOLD}{count_lines(j('endpoints.txt'))}{C.RESET} endpoints")
    return True


def phase_eight(domain_path):
    j = lambda f: os.path.join(domain_path, f)

    if not file_ready(j('merged_way.txt')) and not file_ready(j('endpoints.txt')):
        print_skip("Phase 8 (no URLs)")
        return

    print_phase(8, "GF Pattern Enumeration")

    gf_folder = j('GF')
    os.makedirs(gf_folder, exist_ok=True)
    gf_patterns = [
        "xss", "idor", "lfi", "debug_logic", "img-traversal",
        "interestingEXT", "interestingparams", "interestingsubs",
        "jsvar", "rce", "redirect", "sqli", "ssrf", "ssti"
    ]

    sources = [j('merged_way.txt')]
    if file_ready(j('endpoints.txt')):
        sources.append(j('endpoints.txt'))
    total = merge_files(sources, j('merged_endpoints.txt'))
    print_info(f"Scanning {total} URLs against {len(gf_patterns)} patterns")

    for pattern in gf_patterns:
        outfile = os.path.join(gf_folder, f"{pattern}.txt")
        run_command(
            f"cat {sq(j('merged_endpoints.txt'))} | gf {sq(pattern)} | sort -u > {sq(outfile)}",
            cwd=domain_path, timeout=300
        )

    findings = []
    for pattern in gf_patterns:
        c = count_lines(os.path.join(gf_folder, f"{pattern}.txt"))
        if c > 0:
            findings.append(f"{C.BOLD}{pattern}{C.RESET}:{c}")
    if findings:
        print_success(f"GF hits: {', '.join(findings)}")
    else:
        print_info("No GF pattern matches found")
    print_success("Phase 8 complete")


def phase_nine(domain_path):
    j = lambda f: os.path.join(domain_path, f)

    if not file_ready(j('endpoints.txt')):
        print_skip("Phase 9 (no endpoints available)")
        return

    print_question("Phase 9 scans for exposed API keys (resource-intensive).")
    if not confirm("      proceed? (yes/no): "):
        print_skip("Phase 9")
        return

    print_phase(9, "API Key Scanning")
    run_tool('secretx',
             f"python3 secretx.py --list {sq(j('endpoints.txt'))} --threads 60 "
             f"--output {sq(j('api.txt'))}",
             cwd="/app/secretx/", output_file=j('api.txt'),
             timeout=TOOL_TIMEOUTS['secretx'])
    print_success("Phase 9 complete")


def phase_ten(domain_path):
    j = lambda f: os.path.join(domain_path, f)
    working_count = count_lines(j('workingdomains.txt'))

    if working_count == 0:
        print_skip("Phase 10 (no live hosts)")
        return

    print_question(f"Phase 10 runs nuclei against {working_count} live hosts.")
    log("      This is very resource-intensive and can take hours.")
    if not confirm("      proceed? (yes/no): "):
        print_skip("Phase 10")
        return

    print_phase(10, "Nuclei Vulnerability Scanning")
    run_tool('nuclei',
             f"nuclei -l {sq(j('workingdomains.txt'))} -j -o {sq(j('nuclei.jsonl'))} -silent -nc",
             cwd=domain_path, output_file=j('nuclei.jsonl'),
             timeout=TOOL_TIMEOUTS['nuclei'])

    finding_count = count_lines(j('nuclei.jsonl'))
    print_success(f"Phase 10 complete: {C.BOLD}{finding_count}{C.RESET} findings")

# =============================================================================
# Results output
# =============================================================================

def write_json_summary(domain_path, domain):
    j = lambda f: os.path.join(domain_path, f)

    summary = {
        "domain": domain,
        "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "subdomains": {
            "total": count_lines(j('final_subdomains.txt')),
            "list": read_lines(j('final_subdomains.txt')),
        },
        "live_hosts": {
            "total": count_lines(j('workingdomains.txt')),
            "list": read_lines(j('workingdomains.txt')),
        },
        "dns": {
            "a_records": read_lines(j('a_records.txt')),
            "cname_records": read_lines(j('cname.txt')),
            "ips": read_lines(j('IPs.txt')),
        },
        "asn": [],
        "cidr_ranges": read_lines(j('cidr_ranges.txt')),
        "ports": None,
        "subdomain_takeover": read_lines(j('subdomains_takeover.txt')),
        "gf_patterns": {},
        "nuclei": [],
        "endpoints": {
            "total": count_lines(j('endpoints.txt')),
            "list": read_lines(j('endpoints.txt')),
        },
        "api_keys": {
            "total": count_lines(j('api.txt')),
            "list": read_lines(j('api.txt')),
        },
    }

    if file_ready(j('asn_info.json')):
        try:
            with open(j('asn_info.json'), 'r') as f:
                summary["asn"] = [json.loads(line) for line in f if line.strip()]
        except Exception:
            pass

    if file_ready(j('port_scan.json')):
        try:
            with open(j('port_scan.json'), 'r') as f:
                content = f.read().strip()
                if content:
                    summary["ports"] = json.loads(content)
        except Exception:
            pass

    gf_folder = j('GF')
    if os.path.isdir(gf_folder):
        for fname in sorted(os.listdir(gf_folder)):
            if fname.endswith('.txt'):
                pattern = fname[:-4]
                hits = read_lines(os.path.join(gf_folder, fname))
                if hits:
                    summary["gf_patterns"][pattern] = {
                        "total": len(hits),
                        "urls": hits,
                    }

    if file_ready(j('nuclei.jsonl')):
        try:
            with open(j('nuclei.jsonl'), 'r') as f:
                summary["nuclei"] = [json.loads(line) for line in f if line.strip()]
        except Exception:
            pass

    output_path = j('results.json')
    with open(output_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print_success("Structured results written to results.json")


def summarize_results(domain_path):
    j = lambda f: os.path.join(domain_path, f)

    log(f"\n  {C.W}{C.BOLD}[results]{C.RESET}")

    reports = [
        ("subdomains",       "final_subdomains.txt"),
        ("live hosts",       "workingdomains.txt"),
        ("unique IPs",       "IPs.txt"),
        ("A records",        "a_records.txt"),
        ("CNAME records",    "cname.txt"),
        ("CIDR ranges",      "cidr_ranges.txt"),
        ("endpoints",        "endpoints.txt"),
    ]
    for label, fname in reports:
        count = count_lines(j(fname))
        c = C.W if count > 0 else C.GR
        log(f"  {c}  {label:<20} {count}{C.RESET}")

    gf_folder = j('GF')
    if os.path.isdir(gf_folder):
        gf_total = sum(count_lines(os.path.join(gf_folder, f))
                       for f in os.listdir(gf_folder))
        c = C.W if gf_total > 0 else C.GR
        log(f"  {c}  {'GF matches':<20} {gf_total}{C.RESET}")

    api_count = count_lines(j('api.txt'))
    c = C.R if api_count > 0 else C.GR
    log(f"  {c}  {'api keys':<20} {api_count}{C.RESET}")

    nuclei_count = count_lines(j('nuclei.jsonl'))
    c = C.R if nuclei_count > 0 else C.GR
    log(f"  {c}  {'nuclei findings':<20} {nuclei_count}{C.RESET}")

# =============================================================================
# UI
# =============================================================================

def print_banner():
    try:
        with open(BANNER_PATH, 'r') as f:
            print(f"{C.W}{f.read()}{C.RESET}")
    except FileNotFoundError:
        print(f"\n  {C.W}{C.BOLD}TrashRecon{C.RESET}\n")


def animate():
    chars = '|/-\\'
    i = 0
    while not done.is_set():
        if not _prompt_active.is_set():
            with _print_lock:
                sys.stdout.write(f'\r  {C.GR}[{chars[i]}]{C.RESET}')
                sys.stdout.flush()
            i = (i + 1) % len(chars)
        time.sleep(0.1)
    with _print_lock:
        sys.stdout.write('\r\033[K')
        sys.stdout.flush()


def parse_skip_phases(raw):
    """Parse a comma-separated list of phase numbers into a set of ints."""
    skip = set()
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a phase number: '{part}'")
        if not 1 <= n <= TOTAL_PHASES:
            raise argparse.ArgumentTypeError(
                f"phase out of range (1-{TOTAL_PHASES}): {n}")
        skip.add(n)
    return skip


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="trashrecon",
        description="Automated reconnaissance framework — 17 tools, 10 phases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  trashrecon example.com\n"
            "  trashrecon example.com --yes\n"
            "  trashrecon example.com --skip-phases 4,5,10 -o /data/recon\n"
        ),
    )
    parser.add_argument("domain", nargs="?",
                        help="target domain (prompted if omitted on a TTY)")
    parser.add_argument("-y", "--yes", "--non-interactive",
                        dest="yes", action="store_true",
                        help="auto-proceed optional phases (7, 9, 10) without prompting")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_DIR,
                        metavar="DIR",
                        help=f"output base directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--skip-phases", dest="skip_phases",
                        type=parse_skip_phases, default=set(), metavar="LIST",
                        help="comma-separated phase numbers to skip, e.g. 4,5,10")
    parser.add_argument("--wordlist", default=WORDLIST_PATH, metavar="PATH",
                        help="subdomain brute-force wordlist (default: bundled list)")
    parser.add_argument("--no-color", dest="no_color", action="store_true",
                        help="disable colored output (also honors NO_COLOR)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main():
    global ARGS, WORDLIST_PATH
    ARGS = parse_args()
    WORDLIST_PATH = os.path.expanduser(ARGS.wordlist)

    # Plain text when explicitly disabled, when NO_COLOR is set, or when stdout
    # isn't a terminal (piped/redirected/headless).
    if ARGS.no_color or os.environ.get('NO_COLOR') or not sys.stdout.isatty():
        _disable_colors()

    print_banner()

    domain = ARGS.domain.strip() if ARGS.domain else ''
    if not domain:
        if sys.stdin.isatty():
            try:
                domain = input(f"  {C.W}target:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  aborted.")
                sys.exit(0)
        else:
            print(f"\n  {C.R}[!]{C.RESET} no domain provided.\n")
            print(f"  usage:")
            print(f"    docker run --rm -v ~/TrashRecon:/root/TrashRecon 0xs0m/trashrecon <domain>")
            print(f"    docker run -it --rm -v ~/TrashRecon:/root/TrashRecon 0xs0m/trashrecon\n")
            sys.exit(1)

    domain = domain.lower()
    if not validate_domain(domain):
        log(f"  {C.R}[!]{C.RESET} invalid domain: '{domain}'")
        sys.exit(1)

    domain_path = create_domain_folder(domain)
    setup_logging(domain_path)
    _log_raw(f"Target: {domain}")
    _log_raw(f"Output: {domain_path}")

    if file_ready(os.path.join(domain_path, 'final_subdomains.txt')):
        print_info(f"Existing results found in {domain_path}")
        print_info("Completed steps will be skipped automatically.")

    log(f"  {C.GR}target{C.RESET}  {domain}")
    log(f"  {C.GR}output{C.RESET}  {domain_path}")
    log()

    # Only animate on a real terminal — piped/headless logs stay clean.
    animation_thread = None
    if sys.stdout.isatty():
        animation_thread = threading.Thread(target=animate, daemon=True)
        animation_thread.start()

    skip = ARGS.skip_phases
    if skip:
        print_info(f"Skipping phases: {', '.join(str(n) for n in sorted(skip))}")

    missing = check_dependencies(skip)
    if missing:
        print_warning(f"Missing tools (not on PATH): {', '.join(missing)}")
        print_warning("Affected phases will produce no results.")
        if not confirm("      continue anyway? (yes/no): "):
            print_error("Aborting. Install the missing tools or use --skip-phases.")
            sys.exit(1)

    def should(n):
        return n not in skip

    global _start_time
    _start_time = time.time()
    try:
        if should(1):
            phase_one(domain_path, domain)
        if should(2):
            phase_two(domain_path)
        if should(3):
            phase_three(domain_path)
        if should(4):
            phase_four(domain_path)
        if should(5):
            phase_five(domain_path)
        if should(6):
            phase_six(domain_path)

        ran_seven = should(7) and phase_seven(domain_path, domain)
        # Phase 8 runs on archived URLs (merged_way.txt) even without the crawl;
        # Phase 9 needs the crawl's endpoints.txt, so it stays gated on Phase 7.
        if should(8):
            phase_eight(domain_path)
        if ran_seven and should(9):
            phase_nine(domain_path)

        if should(10):
            phase_ten(domain_path)

        write_json_summary(domain_path, domain)
        summarize_results(domain_path)

        elapsed = time.time() - _start_time
        mins, secs = divmod(int(elapsed), 60)
        hrs, mins = divmod(mins, 60)
        time_str = f"{hrs}h {mins}m {secs}s" if hrs else f"{mins}m {secs}s"

        log(f"\n  {C.G}[+]{C.RESET} done in {time_str}")
        log(f"  {C.GR}    {domain_path}{C.RESET}\n")
    except KeyboardInterrupt:
        log(f"\n\n  {C.R}[!]{C.RESET} interrupted. partial results saved.")
    finally:
        _log_raw(f"Scan ended at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if _log_file:
            _log_file.close()
        done.set()
        if animation_thread is not None:
            animation_thread.join(timeout=2)


if __name__ == "__main__":
    main()
