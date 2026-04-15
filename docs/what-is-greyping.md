# What is GreyPing?

GreyPing is a Docker-first toolkit for **authorised security assessments** that
bundles two complementary services in one image:

1. A hardened **Nuclei passive scanner** — a wrapper around
   [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) tuned
   for small VPS hosts (e.g. a Hetzner CX22 with 2 vCPU / 8 GB / 80 GB).
2. An asynchronous **OSINT Reconnaissance API** — a FastAPI service that
   crawls web targets, fingerprints their stack, mines JavaScript bundles,
   and correlates findings against public OSINT sources.

Both run from the same `docker compose` file. Either one can be used on its
own.

---

## The two services at a glance

### Nuclei passive scanner

Pre-configured nuclei in **passive** mode with conservative concurrency,
automatic template updates persisted to the host, and result logs written
under `data/logs/`. There is also an optional `nuclei-api` HTTP wrapper that
accepts target lists over JSON.

### OSINT Reconnaissance API

A FastAPI app (default port `8089`) that takes a list of domains and returns
structured JSON describing what it found. It is built around a tiered scan
model so the operator can choose how visible the scan should be to the
target's defences.

---

## Scan tiers

The OSINT API exposes four scan tiers, ordered from quietest to loudest:

| Tier              | Endpoint            | Target traffic                                | Use when…                                        |
|-------------------|---------------------|-----------------------------------------------|--------------------------------------------------|
| **Passive**       | `POST /scan/passive`    | Zero packets to the target                | You must not touch the target at all             |
| **Light-touch**   | `POST /scan/lighttouch` | One HTTPS GET (Chrome UA) + one TLS handshake | You want a WAF-friendly snapshot                 |
| **Standard**      | `POST /scan/standard`   | Full crawl, JS mining, breach lookup — but no path dictionary | You want depth without WAF noise |
| **Full**          | `POST /scan`            | Everything, including dictionary path probing (`/.env`, `/.git`, `/admin`, …) | Authorised pentest, no detection concerns |

There is also `POST /scan/quick` — a one-page shallow variant of `/scan` for
fast sanity checks.

### Passive intel sources (no traffic to target)

When `/scan/passive` is invoked, the API queries third-party OSINT sources in
parallel:

- **DNS** via the system resolver (`socket.getaddrinfo`) for A / AAAA records
- **Certificate Transparency** logs via [crt.sh](https://crt.sh) for
  subdomains and issuers
- **RDAP** via [rdap.org](https://rdap.org) for registrar, creation/expiry,
  nameservers, and status
- **Wayback Machine** CDX API for snapshot count and recent archive URLs
- **Have I Been Pwned** (when `HIBP_API_KEY` is configured) for breach hits
  associated with the domain or seed emails

The target sees nothing — all packets go to the third-party services.

---

## Per-capability `/recon/*` endpoints

Beyond the four orchestrators, every individual capability is also reachable
on its own. Useful when an operator wants exactly one piece of intel without
running a full scan.

| Tag           | Endpoint               | What it does                                   |
|---------------|------------------------|------------------------------------------------|
| **network**   | `/recon/ssl`           | TLS certificate analysis                       |
| network       | `/recon/headers`       | Security-header audit (HSTS, CSP, …)           |
| network       | `/recon/cookies`       | Cookie security review                         |
| **content**   | `/recon/crawl`         | Breadth-first crawl                            |
| content       | `/recon/contacts`      | Emails, phones, social profiles with provenance |
| content       | `/recon/links`         | Internal / external link extraction            |
| content       | `/recon/secrets`       | Regex secret scanning (20+ pattern families)   |
| content       | `/recon/ioc`           | Indicators of compromise (cryptominers, hidden iframes, webshells, …) |
| **discovery** | `/recon/paths`         | Sensitive-path probing dictionary              |
| discovery     | `/recon/tech`          | Wappalyzer-style tech fingerprinting           |
| discovery     | `/recon/js`            | JavaScript bundle mining (endpoints, sourcemaps, internal hosts) |
| **intel**     | `/recon/breaches`      | HIBP breach lookups                            |
| **passive**   | `/recon/dns`           | DNS A / AAAA via stdlib resolver               |
| passive       | `/recon/ct`            | Certificate Transparency subdomains            |
| passive       | `/recon/whois`         | RDAP registrar / dates / nameservers           |
| passive       | `/recon/wayback`       | Wayback Machine snapshot history               |

---

## What's inside the OSINT API

| Module                       | Responsibility                                       |
|------------------------------|------------------------------------------------------|
| `src/app.py`                 | FastAPI entrypoint + scan orchestrators              |
| `src/crawler.py`             | Async static + JS-rendered crawler                   |
| `src/extractors.py`          | Contacts, links, page metadata                       |
| `src/secret_scanner.py`      | Regex-based secret detection                         |
| `src/ioc_scanner.py`         | IoC heuristics                                       |
| `src/path_scanner.py`        | Sensitive-path dictionary probing                    |
| `src/security_headers.py`    | Header grading                                       |
| `src/cookie_checker.py`      | Cookie security audit                                |
| `src/ssl_checker.py`         | TLS certificate analysis                             |
| `src/tech_fingerprint.py`    | Wappalyzer-style tech detection                      |
| `src/js_miner.py`            | JS bundle mining (endpoints, internal hosts, maps)   |
| `src/passive_intel.py`       | DNS / CT / RDAP / Wayback                            |
| `src/breach_checker.py`      | HIBP integration                                     |
| `src/routers/`               | Per-capability `/recon/*` endpoints                  |
| `src/models.py`              | Pydantic request / response schemas                  |

---

## Who it's for

GreyPing is aimed at:

- Security teams running **authorised pentests** against assets they own or
  have written permission to test
- Bug-bounty researchers operating within a defined scope
- Defenders running **continuous reconnaissance** against their own
  perimeter to catch drift before an attacker does
- CTF / lab environments and security-research workflows

The four-tier scan ladder is the main lever: an operator can start with
`/scan/passive` (no packets to the target), escalate to `/scan/lighttouch`
(one stealth GET) for a quick WAF-safe view, run `/scan/standard` for full
intelligence without dictionary probing, and only reach for `/scan` when
detection is acceptable.

---

## Responsible use

GreyPing is intended for use against assets you own or for which you have
explicit written authorisation to test. Crawling and breach-correlating
third-party domains without permission may violate applicable laws and the
acceptable-use policies of upstream services (HIBP, target websites, etc.).
Each target submitted to a scan endpoint must be in scope for your
engagement.

For deployment instructions, full request/response schemas, and configuration
details, see the project [README](../README.md).
