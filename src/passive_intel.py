"""Passive OSINT sources.

Every function here queries a *third-party* source and touches nothing
belonging to the target. That makes these calls safe to run against a
target that has a WAF/IDS/bot-manager – the target's edge sees no
traffic from us.

Sources:
  * DNS          – stdlib resolver for A / AAAA; dnspython for MX/NS/TXT/CNAME
  * Email sec.   – SPF/DKIM/DMARC analysis via DNS TXT record lookups
  * CT logs      – https://crt.sh
  * RDAP         – https://rdap.org (JSON-over-HTTPS, RFC 7482-7484)
  * Wayback      – https://archive.org

All functions return a Pydantic result with ``error`` set on failure
instead of raising, matching the pattern used by the active detectors.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any

import dns.resolver
import httpx

from .models import (
    ASNInfo,
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSResult,
    EmailSecurityResult,
    IPEnrichmentResult,
    MXRecord,
    RDAPResult,
    SOARecord,
    SPFResult,
    SRVRecord,
    WaybackResult,
)

logger = logging.getLogger(__name__)

_UA = "GreypingCrawler/1.0 (passive-intel)"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _dns_resolve(domain: str, rdtype: str) -> list[Any]:
    """Blocking helper — resolves one record type via dnspython.

    Returns a list of rdata objects, or empty list on NXDOMAIN / timeout.
    """
    try:
        return list(dns.resolver.resolve(domain, rdtype, lifetime=8))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return []


_SRV_SERVICES = [
    "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp",
    "_http._tcp", "_https._tcp", "_imap._tcp", "_imaps._tcp",
    "_submission._tcp", "_caldav._tcp", "_carddav._tcp",
    "_autodiscover._tcp", "_matrix._tcp",
]


def _resolve_soa(domain: str) -> SOARecord | None:
    try:
        answers = dns.resolver.resolve(domain, "SOA", lifetime=8)
        rr = answers[0]
        return SOARecord(
            primary_ns=str(rr.mname).rstrip("."),
            admin_email=str(rr.rname).rstrip(".").replace(".", "@", 1),
            serial=rr.serial,
            refresh=rr.refresh,
            retry=rr.retry,
            expire=rr.expire,
            minimum_ttl=rr.minimum,
        )
    except Exception:
        return None


def _resolve_srv(domain: str) -> list[SRVRecord]:
    records: list[SRVRecord] = []
    for svc in _SRV_SERVICES:
        try:
            answers = dns.resolver.resolve(f"{svc}.{domain}", "SRV", lifetime=5)
            for rr in answers:
                records.append(SRVRecord(
                    service=svc,
                    priority=rr.priority,
                    weight=rr.weight,
                    port=rr.port,
                    target=str(rr.target).rstrip("."),
                ))
        except Exception:
            continue
    return records


def _resolve_caa(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=8)
        return [f'{rr.flags} {rr.tag} "{rr.value}"' for rr in answers]
    except Exception:
        return []


def _resolve_ptr(ip: str) -> str | None:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=8)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def _check_dnssec(domain: str) -> bool | None:
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=8)
        return True
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return None


async def query_dns(domain: str, *, timeout: int = 15) -> DNSResult:
    """Resolve A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, and DNSSEC.

    A/AAAA use the system resolver (stdlib socket) for maximum compat.
    All other types use dnspython.
    """
    loop = asyncio.get_running_loop()

    def _resolve(family: int) -> list[str]:
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            return sorted({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    try:
        a_task = loop.run_in_executor(None, _resolve, socket.AF_INET)
        aaaa_task = loop.run_in_executor(None, _resolve, socket.AF_INET6)
        mx_task = loop.run_in_executor(None, _dns_resolve, domain, "MX")
        ns_task = loop.run_in_executor(None, _dns_resolve, domain, "NS")
        txt_task = loop.run_in_executor(None, _dns_resolve, domain, "TXT")
        cname_task = loop.run_in_executor(None, _dns_resolve, domain, "CNAME")
        soa_task = loop.run_in_executor(None, _resolve_soa, domain)
        srv_task = loop.run_in_executor(None, _resolve_srv, domain)
        caa_task = loop.run_in_executor(None, _resolve_caa, domain)
        dnssec_task = loop.run_in_executor(None, _check_dnssec, domain)

        (
            a_records, aaaa_records, mx_raw, ns_raw, txt_raw, cname_raw,
            soa_record, srv_records, caa_records, dnssec,
        ) = await asyncio.wait_for(
            asyncio.gather(
                a_task, aaaa_task, mx_task, ns_task, txt_task, cname_task,
                soa_task, srv_task, caa_task, dnssec_task,
            ),
            timeout=timeout,
        )

        mx_records = sorted(
            [MXRecord(priority=r.preference, host=str(r.exchange).rstrip("."))
             for r in mx_raw],
            key=lambda m: m.priority,
        )
        ns_records = sorted(str(r).rstrip(".").lower() for r in ns_raw)
        txt_records = [
            b"".join(r.strings).decode("utf-8", errors="replace")
            for r in txt_raw
        ]
        cname_records = sorted(str(r).rstrip(".").lower() for r in cname_raw)

        # Reverse PTR lookups for each A record (concurrent)
        ptr_tasks = [loop.run_in_executor(None, _resolve_ptr, ip) for ip in a_records]
        ptr_results = await asyncio.wait_for(
            asyncio.gather(*ptr_tasks, return_exceptions=True),
            timeout=10,
        ) if ptr_tasks else []
        ptr_records = [r for r in ptr_results if isinstance(r, str) and r]

        return DNSResult(
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            cname_records=cname_records,
            soa_record=soa_record,
            srv_records=srv_records,
            caa_records=caa_records,
            ptr_records=ptr_records,
            dnssec=dnssec,
        )
    except asyncio.TimeoutError:
        return DNSResult(domain=domain, error="DNS resolution timed out")
    except Exception as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        return DNSResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

async def query_ct_logs(domain: str, *, timeout: int = 15) -> CTResult:
    """Query crt.sh for every cert ever issued for *domain* (incl. subdomains).

    Returns deduped subdomains + unique issuer names.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return CTResult(
                    domain=domain,
                    error=f"crt.sh returned HTTP {resp.status_code}",
                )
            data = resp.json()

        subdomains: set[str] = set()
        issuers: set[str] = set()
        for entry in data or []:
            name_value = entry.get("name_value") or ""
            for host in name_value.splitlines():
                host = host.strip().lower().lstrip("*.")
                if host and host.endswith(domain.lower()):
                    subdomains.add(host)
            cn = (entry.get("common_name") or "").strip().lower().lstrip("*.")
            if cn and cn.endswith(domain.lower()):
                subdomains.add(cn)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)

        return CTResult(
            domain=domain,
            subdomains=sorted(subdomains),
            issuers=sorted(issuers),
            certificates_seen=len(data or []),
        )
    except Exception as exc:
        logger.warning("CT log query failed for %s: %s", domain, exc)
        return CTResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# RDAP (registrar metadata)
# ---------------------------------------------------------------------------

def _rdap_event_date(events: list[dict[str, Any]], action: str) -> str:
    for ev in events or []:
        if (ev.get("eventAction") or "").lower() == action:
            return ev.get("eventDate") or ""
    return ""


def _rdap_registrar(entities: list[dict[str, Any]]) -> str:
    for ent in entities or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        for item in ent.get("vcardArray", [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return ""


def _rdap_nameservers(nameservers: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for ns in nameservers or []:
        name = (ns.get("ldhName") or ns.get("unicodeName") or "").lower()
        if name:
            out.append(name)
    return sorted(set(out))


async def query_rdap(domain: str, *, timeout: int = 15) -> RDAPResult:
    """Look up registrar metadata via rdap.org."""
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/rdap+json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return RDAPResult(domain=domain, error="Domain not found in RDAP")
            if resp.status_code != 200:
                return RDAPResult(
                    domain=domain,
                    error=f"RDAP returned HTTP {resp.status_code}",
                )
            data = resp.json()

        return RDAPResult(
            domain=domain,
            registrar=_rdap_registrar(data.get("entities") or []),
            created=_rdap_event_date(data.get("events") or [], "registration"),
            expires=_rdap_event_date(data.get("events") or [], "expiration"),
            name_servers=_rdap_nameservers(data.get("nameservers") or []),
            status=[s for s in (data.get("status") or []) if isinstance(s, str)],
        )
    except Exception as exc:
        logger.warning("RDAP lookup failed for %s: %s", domain, exc)
        return RDAPResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

def _format_wayback_ts(ts: str) -> str:
    if len(ts) >= 8 and ts.isdigit():
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


async def query_wayback(domain: str, *, timeout: int = 15) -> WaybackResult:
    """Ask archive.org what it knows about *domain*."""
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url={domain}"
        "&output=json&limit=50&from=20000101"
    )
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(cdx_url)
            if resp.status_code != 200:
                return WaybackResult(
                    domain=domain,
                    error=f"Wayback CDX returned HTTP {resp.status_code}",
                )
            rows = resp.json() or []

        # First row is a header
        data_rows = rows[1:] if rows and isinstance(rows[0], list) else []
        if not data_rows:
            return WaybackResult(domain=domain)

        # Columns default order: urlkey, timestamp, original, mimetype, statuscode, digest, length
        timestamps = sorted(r[1] for r in data_rows if len(r) > 1)
        recent = [
            f"https://web.archive.org/web/{r[1]}/{r[2]}"
            for r in data_rows[-10:]
            if len(r) > 2
        ]
        return WaybackResult(
            domain=domain,
            first_seen=_format_wayback_ts(timestamps[0]),
            last_seen=_format_wayback_ts(timestamps[-1]),
            snapshot_count=len(data_rows),
            recent_snapshots=recent,
        )
    except Exception as exc:
        logger.warning("Wayback lookup failed for %s: %s", domain, exc)
        return WaybackResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Email security (SPF / DKIM / DMARC)
# ---------------------------------------------------------------------------

# Common DKIM selectors to try (covers Google, Microsoft, Mailchimp,
# SendGrid, generic defaults).
_DKIM_SELECTORS: list[str] = [
    "google", "selector1", "selector2", "default", "dkim",
    "k1", "s1", "s2", "mail", "mandrill", "smtp",
]

# MX patterns → friendly provider names.
_MX_PROVIDERS: list[tuple[str, str]] = [
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("zoho.com", "Zoho Mail"),
    ("secureserver.net", "GoDaddy"),
    ("emailsrvr.com", "Rackspace"),
    ("wixdns.net", "Wix"),
]


def _parse_spf(txt_records: list[str]) -> SPFResult:
    """Extract SPF from the domain's TXT records and parse key fields."""
    raw = None
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            raw = txt
            break
    if not raw:
        return SPFResult(
            exists=False,
            issues=["No SPF record found"],
        )

    includes = re.findall(r"include:(\S+)", raw, re.I)

    all_qual = None
    m = re.search(r"([+\-~?])all\b", raw)
    if m:
        all_qual = m.group(0)

    issues: list[str] = []
    if all_qual == "+all":
        issues.append("SPF uses +all (pass) — allows any sender, effectively no protection")
    elif all_qual == "?all":
        issues.append("SPF uses ?all (neutral) — provides no enforcement")
    elif all_qual is None:
        issues.append("SPF record missing terminal 'all' mechanism")

    return SPFResult(
        raw=raw,
        exists=True,
        all_qualifier=all_qual,
        includes=includes,
        issues=issues,
    )


def _parse_dmarc(txt_records: list[str]) -> DMARCResult:
    """Parse a DMARC TXT record from the ``_dmarc.`` subdomain."""
    raw = None
    for txt in txt_records:
        if txt.lower().startswith("v=dmarc1"):
            raw = txt
            break
    if not raw:
        return DMARCResult(
            exists=False,
            issues=["No DMARC record found — domain is vulnerable to email spoofing"],
        )

    def _tag(name: str) -> str | None:
        m = re.search(rf"\b{name}\s*=\s*([^;\s]+)", raw, re.I)
        return m.group(1) if m else None

    policy = (_tag("p") or "").lower() or None
    sp = (_tag("sp") or "").lower() or None
    pct_str = _tag("pct")
    pct = int(pct_str) if pct_str and pct_str.isdigit() else 100
    rua = re.findall(r"rua\s*=\s*([^;]+)", raw, re.I)
    rua = [addr.strip() for part in rua for addr in part.split(",")]

    issues: list[str] = []
    if policy == "none":
        issues.append("DMARC policy is 'none' — only monitoring, no enforcement")
    if pct < 100:
        issues.append(f"DMARC pct={pct} — policy only applies to {pct}% of messages")
    if not rua:
        issues.append("DMARC has no rua (aggregate report) address — no visibility into spoofing")

    return DMARCResult(
        raw=raw,
        exists=True,
        policy=policy,
        subdomain_policy=sp,
        pct=pct,
        rua=rua,
        issues=issues,
    )


def _check_dkim(domain: str) -> DKIMResult:
    """Best-effort DKIM selector probing (blocking, run in executor)."""
    found: list[str] = []
    for sel in _DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=5)
            txt = b"".join(answers[0].strings).decode("utf-8", errors="replace")
            if "v=dkim1" in txt.lower() or "p=" in txt:
                found.append(sel)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            continue
    issues: list[str] = []
    if not found:
        issues.append(
            "No DKIM records found for common selectors — "
            "may use a non-standard selector or DKIM is not configured"
        )
    return DKIMResult(
        selectors_checked=list(_DKIM_SELECTORS),
        selectors_found=found,
        issues=issues,
    )


def _detect_mail_providers(mx_records: list[MXRecord]) -> list[str]:
    """Map MX hostnames to friendly provider names."""
    providers: set[str] = set()
    for mx in mx_records:
        host = mx.host.lower()
        for pattern, name in _MX_PROVIDERS:
            if host.endswith(pattern):
                providers.add(name)
                break
    return sorted(providers)


def _grade_email_security(
    spf: SPFResult, dmarc: DMARCResult, dkim: DKIMResult,
) -> str:
    """Assign an A-F grade to overall email security posture."""
    score = 0

    # SPF contribution (0-30)
    if spf.exists:
        if spf.all_qualifier in ("-all",):
            score += 30
        elif spf.all_qualifier in ("~all",):
            score += 20
        else:
            score += 5

    # DMARC contribution (0-40)
    if dmarc.exists:
        if dmarc.policy == "reject":
            score += 40
        elif dmarc.policy == "quarantine":
            score += 30
        elif dmarc.policy == "none":
            score += 10
        if dmarc.pct < 100:
            score -= 5

    # DKIM contribution (0-30)
    if dkim.selectors_found:
        score += 30

    if score >= 90:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


async def query_email_security(
    domain: str, mx_records: list[MXRecord] | None = None, *, timeout: int = 15,
) -> EmailSecurityResult:
    """Analyse SPF, DKIM, DMARC for *domain* via DNS TXT lookups.

    ``mx_records`` is optional — pass the already-resolved MX records
    from ``query_dns`` to avoid a duplicate lookup.
    """
    loop = asyncio.get_running_loop()

    try:
        # TXT on the domain itself (contains SPF).
        txt_task = loop.run_in_executor(None, _dns_resolve, domain, "TXT")
        # TXT on _dmarc subdomain.
        dmarc_task = loop.run_in_executor(
            None, _dns_resolve, f"_dmarc.{domain}", "TXT",
        )
        # DKIM selector probing (multiple DNS queries, heavier).
        dkim_task = loop.run_in_executor(None, _check_dkim, domain)

        domain_txts_raw, dmarc_txts_raw, dkim = await asyncio.wait_for(
            asyncio.gather(txt_task, dmarc_task, dkim_task),
            timeout=timeout,
        )

        domain_txts = [
            b"".join(r.strings).decode("utf-8", errors="replace")
            for r in domain_txts_raw
        ]
        dmarc_txts = [
            b"".join(r.strings).decode("utf-8", errors="replace")
            for r in dmarc_txts_raw
        ]

        spf = _parse_spf(domain_txts)
        dmarc = _parse_dmarc(dmarc_txts)
        providers = _detect_mail_providers(mx_records or [])
        grade = _grade_email_security(spf, dmarc, dkim)

        return EmailSecurityResult(
            domain=domain,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            mail_providers=providers,
            grade=grade,
        )
    except asyncio.TimeoutError:
        return EmailSecurityResult(
            domain=domain, error="Email security lookups timed out",
        )
    except Exception as exc:
        logger.warning("Email security check failed for %s: %s", domain, exc)
        return EmailSecurityResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# IP enrichment via Team Cymru DNS
# ---------------------------------------------------------------------------

# ASN name substrings → friendly hosting provider labels.
_ASN_PROVIDER_PATTERNS: list[tuple[str, str]] = [
    ("CLOUDFLARENET", "Cloudflare"),
    ("AMAZON", "AWS"),
    ("GOOGLE", "Google Cloud"),
    ("MICROSOFT", "Microsoft Azure"),
    ("FASTLY", "Fastly"),
    ("AKAMAI", "Akamai"),
    ("HETZNER", "Hetzner"),
    ("OVH", "OVH"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("LINODE", "Akamai/Linode"),
    ("VULTR", "Vultr"),
    ("IONOS", "IONOS"),
    ("GODADDY", "GoDaddy"),
    ("RACKSPACE", "Rackspace"),
    ("LEASEWEB", "Leaseweb"),
    ("LAYERSHIFT", "Layershift"),
    ("KINSTA", "Kinsta"),
    ("WPENGINE", "WP Engine"),
    ("SITEGROUND", "SiteGround"),
    ("WIX", "Wix"),
    ("SQUARESPACE", "Squarespace"),
    ("SHOPIFY", "Shopify"),
]


def _cymru_origin_lookup(ip: str) -> str | None:
    """Reverse-IP Cymru DNS TXT → 'ASN | prefix | CC | registry | date'."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        rev = ".".join(reversed(parts))
        answers = dns.resolver.resolve(f"{rev}.origin.asn.cymru.com", "TXT", lifetime=8)
        return b"".join(answers[0].strings).decode("utf-8", errors="replace")
    except Exception:
        return None


def _cymru_asn_lookup(asn_num: int) -> str | None:
    """AS-number Cymru DNS TXT → 'ASN | CC | Registry | Date | Name, CC'."""
    try:
        answers = dns.resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT", lifetime=8)
        return b"".join(answers[0].strings).decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_cymru_origin(raw: str) -> tuple[int | None, str, str, str]:
    parts = [p.strip() for p in raw.split("|")]
    asn = int(parts[0]) if parts and parts[0].isdigit() else None
    prefix = parts[1] if len(parts) > 1 else ""
    cc = parts[2] if len(parts) > 2 else ""
    registry = parts[3] if len(parts) > 3 else ""
    return asn, prefix, cc, registry


def _parse_cymru_asn_name(raw: str) -> str:
    parts = [p.strip() for p in raw.split("|")]
    return parts[4] if len(parts) > 4 else ""


def _infer_provider(asn_name: str) -> str | None:
    upper = asn_name.upper()
    for pattern, provider in _ASN_PROVIDER_PATTERNS:
        if pattern in upper:
            return provider
    return None


async def query_ip_enrichment(
    domain: str, a_records: list[str], *, timeout: int = 20,
) -> IPEnrichmentResult:
    """Enrich A records with ASN/hosting/country info via Team Cymru DNS.

    Two TXT lookups per unique IP (origin + ASN name), run concurrently.
    No traffic reaches the target — all queries go to Cymru's resolvers.
    """
    if not a_records:
        return IPEnrichmentResult(domain=domain)

    loop = asyncio.get_running_loop()

    try:
        origin_tasks = [
            loop.run_in_executor(None, _cymru_origin_lookup, ip)
            for ip in a_records
        ]
        origin_raws = await asyncio.wait_for(
            asyncio.gather(*origin_tasks, return_exceptions=True),
            timeout=timeout,
        )

        ip_parsed: dict[str, tuple[int | None, str, str, str]] = {}
        unique_asns: set[int] = set()
        for ip, raw in zip(a_records, origin_raws):
            if isinstance(raw, Exception) or not raw:
                ip_parsed[ip] = (None, "", "", "")
            else:
                parsed = _parse_cymru_origin(raw)
                ip_parsed[ip] = parsed
                if parsed[0]:
                    unique_asns.add(parsed[0])

        asn_name_tasks = [
            loop.run_in_executor(None, _cymru_asn_lookup, asn)
            for asn in unique_asns
        ]
        asn_name_raws = await asyncio.wait_for(
            asyncio.gather(*asn_name_tasks, return_exceptions=True),
            timeout=timeout,
        )
        asn_name_map: dict[int, str] = {}
        for asn, raw in zip(unique_asns, asn_name_raws):
            if not isinstance(raw, Exception) and raw:
                asn_name_map[asn] = _parse_cymru_asn_name(raw)

        records: list[ASNInfo] = []
        providers: list[str] = []
        countries: set[str] = set()
        for ip in a_records:
            asn, prefix, cc, registry = ip_parsed.get(ip, (None, "", "", ""))
            asn_name = asn_name_map.get(asn, "") if asn else ""
            records.append(ASNInfo(
                ip=ip, asn=asn, asn_name=asn_name,
                prefix=prefix, country_code=cc, registry=registry,
            ))
            if cc:
                countries.add(cc)
            if asn_name:
                p = _infer_provider(asn_name)
                if p and p not in providers:
                    providers.append(p)

        return IPEnrichmentResult(
            domain=domain,
            records=records,
            hosting_providers=providers,
            countries=sorted(countries),
        )
    except asyncio.TimeoutError:
        return IPEnrichmentResult(domain=domain, error="IP enrichment timed out")
    except Exception as exc:
        logger.warning("IP enrichment failed for %s: %s", domain, exc)
        return IPEnrichmentResult(domain=domain, error=str(exc))
