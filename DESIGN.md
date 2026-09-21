# TrashRecon v2 — Design notes

Status: draft (R&D). Branch: `rd/recon-v2`.  
Researched: 2026-09-21 (IST). No pipeline code changes in this commit.

## Current state (v1.1.0)

Linear 10-phase Docker wrapper around ~17 tools. Strong base: subfinder, httpx, dnsx, asnmap, katana, nuclei, puredns/massdns, waymore, secretx.

Gaps that feel dated:

- No subdomain permutations after passive seeds
- Port scan is smap-only (Shodan passive)
- Screenshots via aquatone fork (upstream archived)
- waybackurls overlaps gau/waymore
- httpx keeps only 200/3xx; no tech-detect / screenshots in-probe
- DNS phase runs only on live hosts (takeover already uses all resolved)
- No JS mining, no optional fuzzing, no CIDR→host expansion for scanning
- amass still installed as v3; Docker pins many tools at `@latest`

## Goals

1. Better coverage with a clearer stage model (Discover → Resolve → Probe → Enrich → Deep)
2. Prefer maintained Go / ProjectDiscovery tools that Dockerize cleanly
3. Profiles: `quick` / `standard` / `deep` (optional heavy phases gated)
4. Keep resume + `--skip-phases`; add `--force` later (engine hygiene)

Non-goals for this doc: rewrite of `trashrecon.py`, secretx redesign, office/AppSec productization.

---

## Tool shortlist

### Must consider (ranked)

| Rank | Tool | Action | Phase / gap |
|------|------|--------|-------------|
| 1 | [alterx](https://github.com/projectdiscovery/alterx) | **ADD** | Phase 1 — permutations after passive seeds |
| 2 | [naabu](https://github.com/projectdiscovery/naabu) | **REPLACE/COMPLEMENT** smap | Phase 4 — active ports |
| 3 | httpx `-td` / `-ss` (+ optional [gowitness](https://github.com/sensepost/gowitness)) | **REPLACE** aquatone | Phase 1/5 — tech + screenshots |
| 4 | [tlsx](https://github.com/projectdiscovery/tlsx) | **ADD** | Phase 1–2 — TLS/SAN feedback loop |
| 5 | [gau](https://github.com/lc/gau) | **ADD**; demote waybackurls | URL harvest |
| 6 | [ffuf](https://github.com/ffuf/ffuf) | **ADD** (optional phase) | Content discovery |
| 7 | [jsluice](https://github.com/BishopFox/jsluice) | **ADD** | Post-katana JS extract |
| 8 | [mapcidr](https://github.com/projectdiscovery/mapcidr) | **ADD** | Phase 3 — CIDR → IPs (capped) |
| 9 | [github-subdomains](https://github.com/gwen001/github-subdomains) | **OPTIONAL ADD** | Phase 1 — GitHub OSINT (needs token) |
| 10 | [gitleaks](https://github.com/gitleaks/gitleaks) | **ADD/COMPLEMENT** secretx | Phase 9 — secrets on JS/response corpus |

Honorable: [uncover](https://github.com/projectdiscovery/uncover), [cloud_enum](https://github.com/initstring/cloud_enum), [cero](https://github.com/glebarez/cero), nuclei `-tags takeover`, [chaos-client](https://github.com/projectdiscovery/chaos-client).

### Demote / revisit (already in image)

| Tool | Verdict |
|------|---------|
| aquatone (fork) | Demote → replace with httpx `-ss` or gowitness |
| waybackurls | Demote → gau + waymore |
| assetfinder | Demote / optional → largely ⊆ subfinder |
| amass v3 | Revisit v5 or drop if subfinder + API sources suffice |
| smap alone | Keep as passive pass; not sole scanner |
| subzy alone | Keep + add nuclei takeover templates |
| gotator / dnsgen | Skip — prefer alterx |

### Keep as-is

puredns, massdns, subfinder, httpx, dnsx, asnmap, katana, nuclei, waymore, secretx, gf (+ refresh patterns opportunistically).

---

## Proposed pipeline

```
Phase 1 Discover
  subfinder (+API sources) | amass? | github-subdomains?
  → alterx (-limit / -enrich) → puredns resolve
  → tlsx SAN loop → merge in-scope hosts
  → httpx (-td [-ss]; widen status codes beyond 200/3xx)

Phase 2 Resolve / DNS
  dnsx on all resolved names (not only live)

Phase 3 Enrich net
  asnmap → mapcidr (hard size cap) → optional uncover / cloud_enum

Phase 4 Ports
  smap (passive, fast) + naabu (active; default top-ports, full optional)

Phase 5 Screenshots
  Prefer httpx -ss; else gowitness. Drop aquatone.

Phase 6 Takeover
  subzy on final_subdomains + nuclei -tags takeover

Phase 7 Crawl / URLs
  katana (-jc) → jsluice
  gau ∥ waymore (drop waybackurls)
  gf on merged URL corpus

Phase 7.5 / 11 Fuzz (optional)
  ffuf (rate-limited; SecLists paths; gated like nuclei)

Phase 9 Secrets
  secretx + gitleaks on JS / response dumps

Phase 10 Vuln
  nuclei on hosts and/or URLs (profile-dependent)
```

### Profiles (suggested)

| Profile | Runs |
|---------|------|
| `quick` | 1 (no alterx blow-up / capped), 2, 6, httpx -td; skip crawl/ffuf/nuclei/secretx |
| `standard` | + alterx capped, naabu top-ports, gau, katana, gf, subzy+takeover nuclei |
| `deep` | + mapcidr (capped), full optional: ffuf, secretx, gitleaks, nuclei, screenshots |

---

## Implementation tracks (ordered)

1. **Flow redesign** — stage deps, profiles, widen httpx, DNS on all resolved  
2. **Tool refresh** — shortlist above; pin versions in Dockerfile (prefer PD releases / pdtm over floating `@latest`)  
3. **Engine hygiene** — `--force`, leaner `results.json`, fewer `shell=True` commands, more tests  
4. **Ship** — version bump, README phase diagram, rebuild `0xs0m/trashrecon`

First code milestone after this doc: `quick` profile + alterx→puredns wire-up on this branch (separate PR/commits).

---

## Docker notes

```text
# Prefer pinned release binaries / pdtm in Dockerfile
go install github.com/projectdiscovery/alterx/cmd/alterx@<pin>
go install github.com/projectdiscovery/tlsx/cmd/tlsx@<pin>
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@<pin>
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@<pin>
go install github.com/lc/gau/v2/cmd/gau@<pin>
go install github.com/ffuf/ffuf/v2@<pin>
go install github.com/BishopFox/jsluice/cmd/jsluice@<pin>
# gitleaks: GitHub release binary
# naabu SYN scan: docker --cap-add=NET_RAW --cap-add=NET_ADMIN (or connect-scan without)
```

Feature-flag anything that needs API keys: Chaos, uncover, github-subdomains / subfinder github.

---

## Open decisions

- amass: upgrade to v5, passive-only, or remove?
- Screenshots: httpx `-ss` only vs keep a dedicated gowitness phase?
- Default profile for Docker ENTRYPOINT: `standard` or `quick`?
- Should `rd/recon-v2` land as one large PR or stacked PRs (flow → tools → hygiene)?

---

## References

- Current README phase list and tool table in this repo  
- Tool R&D pass 2026-09-21 (GitHub metadata + ProjectDiscovery docs; no local clones required for this doc)
