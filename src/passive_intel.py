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
    ARecord,
    AAAARecord,
    ASNInfo,
    BIMIResult,
    CAARecord,
    CNAMERecord,
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSResult,
    DSRecord,
    EmailSecurityResult,
    HINFORecord,
    IPEnrichmentResult,
    LOCRecord,
    MTASTSResult,
    MXRecordFull,
    NAPTRRecord,
    NSRecord,
    RDAPResult,
    RPRecord,
    SOARecord,
    SPFIncludeNode,
    SPFIntelResult,
    SPFMechanism,
    SPFResult,
    SPFSenderInfo,
    SRVRecord,
    SSHFPRecord,
    TLSARecord,
    TXTRecord,
    WaybackResult,
)

from .config import DNS_LIFETIME, PASSIVE_TIMEOUT, UA_HONEST

logger = logging.getLogger(__name__)

_UA = f"{UA_HONEST} (passive-intel)"

_DNS_SEMAPHORE = asyncio.Semaphore(10)


async def _bounded_executor(fn, *args):
    """Run a blocking function in the default executor, bounded by _DNS_SEMAPHORE."""
    loop = asyncio.get_running_loop()
    async with _DNS_SEMAPHORE:
        return await loop.run_in_executor(None, fn, *args)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _dns_resolve(domain: str, rdtype: str) -> list[Any]:
    """Blocking helper — resolves one record type via dnspython.

    Returns a list of rdata objects, or empty list on NXDOMAIN / timeout.
    """
    try:
        return list(dns.resolver.resolve(domain, rdtype, lifetime=DNS_LIFETIME))
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
        answers = dns.resolver.resolve(domain, "SOA", lifetime=DNS_LIFETIME)
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
            answers = dns.resolver.resolve(f"{svc}.{domain}", "SRV", lifetime=DNS_LIFETIME)
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


def _resolve_caa(domain: str) -> list[CAARecord]:
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, 'rrset') else 0
        return [
            CAARecord(flags=rr.flags, tag=rr.tag.decode() if isinstance(rr.tag, bytes) else rr.tag,
                     value=rr.value.decode() if isinstance(rr.value, bytes) else rr.value, ttl=ttl)
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_ptr(ip: str) -> str | None:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=DNS_LIFETIME)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def _check_dnssec(domain: str) -> bool | None:
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=DNS_LIFETIME)
        return True
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return None


_TLSA_PORTS = [
    (25, "tcp"),
    (443, "tcp"),
    (993, "tcp"),
    (995, "tcp"),
]


def _resolve_tlsa(domain: str) -> list[TLSARecord]:
    records: list[TLSARecord] = []
    for port, proto in _TLSA_PORTS:
        try:
            answers = dns.resolver.resolve(f"_{port}._{proto}.{domain}", "TLSA", lifetime=DNS_LIFETIME)
            ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
            for rr in answers:
                records.append(TLSARecord(
                    usage=rr.usage,
                    selector=rr.selector,
                    matching_type=rr.mtype,
                    certificate_data=rr.cert.hex(),
                    port=port,
                    protocol=proto,
                    ttl=ttl,
                ))
        except Exception:
            continue
    return records


def _resolve_sshfp(domain: str) -> list[SSHFPRecord]:
    try:
        answers = dns.resolver.resolve(domain, "SSHFP", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            SSHFPRecord(
                algorithm=rr.algorithm,
                fingerprint_type=rr.fp_type,
                fingerprint=rr.fingerprint.hex(),
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_ds(domain: str) -> list[DSRecord]:
    try:
        answers = dns.resolver.resolve(domain, "DS", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            DSRecord(
                key_tag=rr.key_tag,
                algorithm=rr.algorithm,
                digest_type=rr.digest_type,
                digest=rr.digest.hex(),
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_naptr(domain: str) -> list[NAPTRRecord]:
    try:
        answers = dns.resolver.resolve(domain, "NAPTR", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            NAPTRRecord(
                order=rr.order,
                preference=rr.preference,
                flags=rr.flags.decode("ascii", errors="replace") if isinstance(rr.flags, bytes) else str(rr.flags),
                service=rr.service.decode("ascii", errors="replace") if isinstance(rr.service, bytes) else str(rr.service),
                regexp=rr.regexp.decode("utf-8", errors="replace") if isinstance(rr.regexp, bytes) else str(rr.regexp),
                replacement=str(rr.replacement).rstrip("."),
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_loc(domain: str) -> list[LOCRecord]:
    try:
        answers = dns.resolver.resolve(domain, "LOC", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            LOCRecord(
                latitude=rr.float_latitude,
                longitude=rr.float_longitude,
                altitude=(rr.altitude / 100.0) - 100000.0,
                size=rr.size / 100.0,
                horizontal_precision=rr.horizontal_precision / 100.0,
                vertical_precision=rr.vertical_precision / 100.0,
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_rp(domain: str) -> list[RPRecord]:
    try:
        answers = dns.resolver.resolve(domain, "RP", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            RPRecord(
                mbox=str(rr.mbox).rstrip(".").replace(".", "@", 1),
                txt_domain=str(rr.txt).rstrip("."),
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


def _resolve_hinfo(domain: str) -> list[HINFORecord]:
    try:
        answers = dns.resolver.resolve(domain, "HINFO", lifetime=DNS_LIFETIME)
        ttl = answers.rrset.ttl if hasattr(answers, "rrset") else 0
        return [
            HINFORecord(
                cpu=rr.cpu.decode("utf-8", errors="replace") if isinstance(rr.cpu, bytes) else str(rr.cpu),
                os=rr.os.decode("utf-8", errors="replace") if isinstance(rr.os, bytes) else str(rr.os),
                ttl=ttl,
            )
            for rr in answers
        ]
    except Exception:
        return []


async def query_dns(domain: str, *, timeout: int = PASSIVE_TIMEOUT) -> DNSResult:
    """Resolve A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, DNSSEC,
    TLSA, SSHFP, DS, NAPTR, LOC, RP, and HINFO.

    A/AAAA use the system resolver (stdlib socket) for maximum compat.
    All other types use dnspython.
    """
    loop = asyncio.get_running_loop()

    def _resolve(family: int) -> list[str]:
        """Resolve A/AAAA records via stdlib socket (returns IP addresses only)."""
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            return sorted({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    def _get_ttl_for_a_record(domain: str, ip: str) -> int:
        """Best-effort: try to get TTL from dnspython if available, else default to 0."""
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=DNS_LIFETIME)
            for rr in answers.rrset:
                if str(rr) == ip:
                    return answers.rrset.ttl
        except Exception:
            pass
        return 0

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
        tlsa_task = loop.run_in_executor(None, _resolve_tlsa, domain)
        sshfp_task = loop.run_in_executor(None, _resolve_sshfp, domain)
        ds_task = loop.run_in_executor(None, _resolve_ds, domain)
        naptr_task = loop.run_in_executor(None, _resolve_naptr, domain)
        loc_task = loop.run_in_executor(None, _resolve_loc, domain)
        rp_task = loop.run_in_executor(None, _resolve_rp, domain)
        hinfo_task = loop.run_in_executor(None, _resolve_hinfo, domain)

        (
            a_records, aaaa_records, mx_raw, ns_raw, txt_raw, cname_raw,
            soa_record, srv_records, caa_records, dnssec,
            tlsa_records, sshfp_records, ds_records, naptr_records,
            loc_records, rp_records, hinfo_records,
        ) = await asyncio.wait_for(
            asyncio.gather(
                a_task, aaaa_task, mx_task, ns_task, txt_task, cname_task,
                soa_task, srv_task, caa_task, dnssec_task,
                tlsa_task, sshfp_task, ds_task, naptr_task,
                loc_task, rp_task, hinfo_task,
            ),
            timeout=timeout,
        )

        # Get TTL from answer sets (all records in a set have the same TTL)
        # MX records with TTL
        mx_ttl = getattr(mx_raw, 'ttl', 0) if hasattr(mx_raw, 'ttl') else (mx_raw[0].ttl if mx_raw and hasattr(mx_raw[0], 'ttl') else 0)
        mx_records_full = sorted(
            [MXRecordFull(
                priority=r.preference,
                host=str(r.exchange).rstrip("."),
                ttl=mx_ttl,
            ) for r in mx_raw],
            key=lambda m: m.priority,
        )

        # NS records with TTL
        ns_ttl = getattr(ns_raw, 'ttl', 0) if hasattr(ns_raw, 'ttl') else 0
        ns_records_full = [
            NSRecord(host=str(r).rstrip(".").lower(), ttl=ns_ttl)
            for r in ns_raw
        ]

        # TXT records with TTL and parsed entries
        txt_ttl = getattr(txt_raw, 'ttl', 0) if hasattr(txt_raw, 'ttl') else 0
        txt_records_full = [
            TXTRecord(
                data=b"".join(r.strings).decode("utf-8", errors="replace"),
                ttl=txt_ttl,
                entries=[b"".join(r.strings).decode("utf-8", errors="replace")],
            )
            for r in txt_raw
        ]

        # CNAME records with TTL
        cname_ttl = getattr(cname_raw, 'ttl', 0) if hasattr(cname_raw, 'ttl') else 0
        cname_records_full = [
            CNAMERecord(target=str(r).rstrip(".").lower(), ttl=cname_ttl)
            for r in cname_raw
        ]

        # Reverse PTR lookups for each A record (concurrent, bounded)
        ptr_tasks = [_bounded_executor(_resolve_ptr, ip) for ip in a_records]
        ptr_results = await asyncio.wait_for(
            asyncio.gather(*ptr_tasks, return_exceptions=True),
            timeout=DNS_LIFETIME + 2,
        ) if ptr_tasks else []
        ptr_map = {a_records[i]: ptr_results[i] if isinstance(ptr_results[i], str) else ""
                   for i in range(len(a_records))}

        # A records with TTL and reverse DNS
        a_records_full = [
            ARecord(address=ip, ttl=_get_ttl_for_a_record(domain, ip), reverse=ptr_map.get(ip, ""))
            for ip in a_records
        ]

        # AAAA records with TTL and reverse DNS (attempt)
        aaaa_records_full = [
            AAAARecord(address=ip, ttl=0, reverse="")  # TTL extraction for AAAA is similar
            for ip in aaaa_records
        ]

        return DNSResult(
            domain=domain,
            a_records=a_records_full,
            aaaa_records=aaaa_records_full,
            mx_records=mx_records_full,
            ns_records=ns_records_full,
            txt_records=txt_records_full,
            cname_records=cname_records_full,
            soa_record=soa_record,
            srv_records=srv_records,
            caa_records=caa_records,
            ptr_records=[r for r in ptr_results if isinstance(r, str) and r],
            dnssec=dnssec,
            tlsa_records=tlsa_records,
            sshfp_records=sshfp_records,
            ds_records=ds_records,
            naptr_records=naptr_records,
            loc_records=loc_records,
            rp_records=rp_records,
            hinfo_records=hinfo_records,
        )
    except asyncio.TimeoutError:
        return DNSResult(domain=domain, error="DNS resolution timed out")
    except Exception as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        return DNSResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

async def query_ct_logs(domain: str, *, timeout: int = PASSIVE_TIMEOUT) -> CTResult:
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


async def query_rdap(domain: str, *, timeout: int = PASSIVE_TIMEOUT) -> RDAPResult:
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


async def query_wayback(domain: str, *, timeout: int = PASSIVE_TIMEOUT) -> WaybackResult:
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
    "google", "selector1", "selector2", "default", "dkim", "k1",
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


# ---------------------------------------------------------------------------
# SPF deep enumeration — mechanism parsing, include tree, IP enrichment
# ---------------------------------------------------------------------------

_SPF_INCLUDE_SERVICE_MAP: dict[str, str] = {
    "_spf.google.com": "Google Workspace",
    "_netblocks.google.com": "Google Workspace",
    "_netblocks2.google.com": "Google Workspace",
    "_netblocks3.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "spf.messagelabs.com": "Broadcom Email Security",
    "spf.mandrillapp.com": "Mailchimp Transactional",
    "servers.mcsv.net": "Mailchimp",
    "mail.zendesk.com": "Zendesk",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "spf.mtasv.net": "Postmark",
    "mktomail.com": "Marketo",
    "spf.sendinblue.com": "Brevo",
    "stspg-customer.com": "StatusPage",
    "spf.freshdesk.com": "Freshdesk",
    "spf1.hubspot.com": "HubSpot",
    "helpscoutemail.com": "Help Scout",
    "mxlogin.com": "Intermedia",
    "pphosted.com": "Proofpoint",
    "firebasemail.com": "Firebase",
    "mailgun.org": "Mailgun",
    "zoho.com": "Zoho Mail",
    "outbound.mailhop.org": "DynECT",
    "aspmx.googlemail.com": "Google Workspace",
    "mailsenders.netsuite.com": "NetSuite",
    "spf.constantcontact.com": "Constant Contact",
    "em.sailthru.com": "Sailthru",
    "cust-spf.exacttarget.com": "Salesforce Marketing Cloud",
    "spf.campaignmonitor.com": "Campaign Monitor",
    "mimecast.com": "Mimecast",
}

_SPF_MECHANISM_RE = re.compile(
    r"^([+\-~?])?"
    r"(ip4|ip6|all|include|redirect|exists|ptr|mx|a)"
    r"(?:[=:/](\S+))?$",
    re.I,
)


def _parse_spf_mechanisms(raw: str) -> list[SPFMechanism]:
    """Parse all mechanisms from a raw SPF record."""
    mechanisms: list[SPFMechanism] = []
    tokens = raw.split()
    for token in tokens:
        if token.lower().startswith("v=spf1"):
            continue
        m = _SPF_MECHANISM_RE.match(token)
        if m:
            qual = m.group(1) or "+"
            mech = m.group(2).lower()
            val = m.group(3) or ""
            if mech == "redirect":
                qual = ""
            mechanisms.append(SPFMechanism(qualifier=qual, mechanism=mech, value=val))
    return mechanisms


def _map_include_to_service(domain: str) -> str:
    """Map an SPF include domain to a known third-party service."""
    domain_lower = domain.lower().rstrip(".")
    for pattern, service in _SPF_INCLUDE_SERVICE_MAP.items():
        if pattern in domain_lower:
            return service
    return ""


def _resolve_spf_record(domain: str) -> str | None:
    """Blocking: resolve a single SPF TXT record for *domain*."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_LIFETIME)
        for rr in answers:
            txt = b"".join(rr.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return None


def _walk_spf_tree(
    domain: str, depth: int, max_depth: int, visited: set[str],
) -> tuple[SPFIncludeNode, int]:
    """Recursively resolve SPF includes. Returns (node, dns_lookups_consumed)."""
    domain = domain.lower().rstrip(".")
    if domain in visited or depth > max_depth:
        return SPFIncludeNode(domain=domain, error="max depth or cycle"), 0
    visited.add(domain)

    raw = _resolve_spf_record(domain)
    if not raw:
        return SPFIncludeNode(domain=domain, error="no SPF record found"), 1

    node = SPFIncludeNode(
        domain=domain,
        raw_record=raw,
        service=_map_include_to_service(domain),
    )

    lookups = 1
    mechanisms = _parse_spf_mechanisms(raw)
    for mech in mechanisms:
        if mech.mechanism == "ip4" and mech.value:
            node.ip4_ranges.append(mech.value)
        elif mech.mechanism == "ip6" and mech.value:
            node.ip6_ranges.append(mech.value)
        elif mech.mechanism in ("include", "redirect") and mech.value:
            child, child_lookups = _walk_spf_tree(
                mech.value, depth + 1, max_depth, visited,
            )
            node.children.append(child)
            lookups += child_lookups
        elif mech.mechanism in ("a", "mx"):
            lookups += 1

    return node, lookups


def _collect_ranges(node: SPFIncludeNode) -> tuple[list[str], list[str]]:
    """Flatten all ip4/ip6 ranges from an include tree."""
    ip4: list[str] = list(node.ip4_ranges)
    ip6: list[str] = list(node.ip6_ranges)
    for child in node.children:
        c4, c6 = _collect_ranges(child)
        ip4.extend(c4)
        ip6.extend(c6)
    return ip4, ip6


def _collect_services(node: SPFIncludeNode) -> list[str]:
    """Collect all mapped service names from an include tree."""
    services: list[str] = []
    if node.service:
        services.append(node.service)
    for child in node.children:
        services.extend(_collect_services(child))
    return services


def _ip_from_cidr(cidr: str) -> str | None:
    """Extract a single representative IP from a CIDR or bare IP."""
    ip = cidr.split("/")[0]
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ip
    return None


async def enumerate_spf(
    domain: str,
    spf_result: SPFResult,
    *,
    timeout: int = PASSIVE_TIMEOUT,
) -> SPFIntelResult:
    """Deep SPF enumeration: parse mechanisms, resolve include tree, enrich IPs.

    All queries are passive DNS lookups — zero traffic to the target.
    """
    if not spf_result.exists or not spf_result.raw:
        return SPFIntelResult(domain=domain)

    try:
        mechanisms = _parse_spf_mechanisms(spf_result.raw)

        root_ip4: list[str] = []
        root_ip6: list[str] = []
        include_domains: list[str] = []
        redirect_domain: str | None = None
        root_lookups = 0

        for mech in mechanisms:
            if mech.mechanism == "ip4" and mech.value:
                root_ip4.append(mech.value)
            elif mech.mechanism == "ip6" and mech.value:
                root_ip6.append(mech.value)
            elif mech.mechanism == "include" and mech.value:
                include_domains.append(mech.value)
            elif mech.mechanism == "redirect" and mech.value:
                redirect_domain = mech.value
            elif mech.mechanism in ("a", "mx"):
                root_lookups += 1

        # Resolve include tree in executor (blocking DNS).
        visited: set[str] = {domain.lower().rstrip(".")}
        include_tree: list[SPFIncludeNode] = []
        total_lookups = root_lookups

        all_targets = include_domains + ([redirect_domain] if redirect_domain else [])

        async def _resolve_one(inc_domain: str) -> tuple[SPFIncludeNode, int]:
            return await _bounded_executor(
                _walk_spf_tree, inc_domain, 1, 10, visited,
            )

        if all_targets:
            results = await asyncio.wait_for(
                asyncio.gather(*[_resolve_one(d) for d in all_targets], return_exceptions=True),
                timeout=timeout,
            )
            for r in results:
                if isinstance(r, Exception):
                    logger.debug("SPF include resolution failed: %s", r)
                    continue
                node, lookups = r
                include_tree.append(node)
                total_lookups += lookups

        # Collect all ranges from root + include tree.
        all_ip4 = list(root_ip4)
        all_ip6 = list(root_ip6)
        for node in include_tree:
            c4, c6 = _collect_ranges(node)
            all_ip4.extend(c4)
            all_ip6.extend(c6)

        # Collect services.
        services: list[str] = []
        for inc in include_domains:
            svc = _map_include_to_service(inc)
            if svc and svc not in services:
                services.append(svc)
        for node in include_tree:
            for svc in _collect_services(node):
                if svc and svc not in services:
                    services.append(svc)

        # Extract unique IPs for enrichment (take first IP from each CIDR).
        unique_ips: list[str] = []
        seen_ips: set[str] = set()
        ip_sources: dict[str, str] = {}
        for cidr in all_ip4:
            ip = _ip_from_cidr(cidr)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                unique_ips.append(ip)
                ip_sources[ip] = f"ip4:{cidr}"

        # Enrich IPs via Cymru (reuse existing functions).
        senders: list[SPFSenderInfo] = []
        if unique_ips:
            try:
                origin_tasks = [
                    _bounded_executor(_cymru_origin_lookup, ip)
                    for ip in unique_ips
                ]
                origin_raws = await asyncio.wait_for(
                    asyncio.gather(*origin_tasks, return_exceptions=True),
                    timeout=timeout,
                )

                ip_parsed: dict[str, tuple[int | None, str, str, str]] = {}
                unique_asns: set[int] = set()
                for ip, raw in zip(unique_ips, origin_raws):
                    if isinstance(raw, Exception) or not raw:
                        ip_parsed[ip] = (None, "", "", "")
                    else:
                        parsed = _parse_cymru_origin(raw)
                        ip_parsed[ip] = parsed
                        if parsed[0]:
                            unique_asns.add(parsed[0])

                asn_name_tasks = [
                    _bounded_executor(_cymru_asn_lookup, asn)
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

                for ip in unique_ips:
                    asn, prefix, cc, registry = ip_parsed.get(ip, (None, "", "", ""))
                    asn_name = asn_name_map.get(asn, "") if asn else ""
                    provider = _infer_provider(asn_name) if asn_name else ""
                    senders.append(SPFSenderInfo(
                        ip=ip,
                        source=ip_sources.get(ip, ""),
                        asn=asn,
                        asn_name=asn_name,
                        prefix=prefix,
                        country_code=cc,
                        provider=provider,
                    ))
            except Exception as exc:
                logger.debug("SPF IP enrichment failed: %s", exc)

        exceeds = total_lookups > 10
        if exceeds:
            spf_result.issues.append(
                f"SPF exceeds 10-lookup limit ({total_lookups} lookups) — "
                "receiving servers may return permerror"
            )

        intel = SPFIntelResult(
            domain=domain,
            mechanisms=mechanisms,
            include_tree=include_tree,
            ip4_ranges=all_ip4,
            ip6_ranges=all_ip6,
            senders=senders,
            services_detected=services,
            dns_lookup_count=total_lookups,
            exceeds_lookup_limit=exceeds,
        )
        return intel

    except asyncio.TimeoutError:
        return SPFIntelResult(domain=domain, error="SPF enumeration timed out")
    except Exception as exc:
        logger.warning("SPF enumeration failed for %s: %s", domain, exc)
        return SPFIntelResult(domain=domain, error=str(exc))


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
            answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_LIFETIME)
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


def _check_mta_sts(domain: str) -> MTASTSResult:
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT", lifetime=DNS_LIFETIME)
        for rr in answers:
            txt = b"".join(rr.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=stsv1"):
                version = ""
                sts_id = ""
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("v="):
                        version = part.split("=", 1)[1].strip()
                    elif part.lower().startswith("id="):
                        sts_id = part.split("=", 1)[1].strip()
                return MTASTSResult(raw=txt, exists=True, version=version, sts_id=sts_id)
    except Exception:
        pass
    return MTASTSResult(exists=False, issues=["No MTA-STS TXT record found"])


def _check_bimi(domain: str) -> BIMIResult:
    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=DNS_LIFETIME)
        for rr in answers:
            txt = b"".join(rr.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=bimi1"):
                version = ""
                logo_url = ""
                authority_url = ""
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("v="):
                        version = part.split("=", 1)[1].strip()
                    elif part.lower().startswith("l="):
                        logo_url = part.split("=", 1)[1].strip()
                    elif part.lower().startswith("a="):
                        authority_url = part.split("=", 1)[1].strip()
                issues: list[str] = []
                if not logo_url:
                    issues.append("BIMI record has no logo URL (l= tag)")
                return BIMIResult(
                    raw=txt, exists=True, version=version,
                    logo_url=logo_url, authority_url=authority_url, issues=issues,
                )
    except Exception:
        pass
    return BIMIResult(exists=False, issues=["No BIMI record found"])


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
    mta_sts: MTASTSResult | None = None, bimi: BIMIResult | None = None,
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

    # MTA-STS bonus (0-10)
    if mta_sts and mta_sts.exists:
        score += 10

    # BIMI bonus (0-5)
    if bimi and bimi.exists and bimi.logo_url:
        score += 5

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
    domain: str, mx_records: list[MXRecord] | None = None, *, timeout: int = PASSIVE_TIMEOUT,
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
        dkim_task = _bounded_executor(_check_dkim, domain)
        mta_sts_task = _bounded_executor(_check_mta_sts, domain)
        bimi_task = _bounded_executor(_check_bimi, domain)

        domain_txts_raw, dmarc_txts_raw, dkim, mta_sts, bimi = await asyncio.wait_for(
            asyncio.gather(txt_task, dmarc_task, dkim_task, mta_sts_task, bimi_task),
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
        grade = _grade_email_security(spf, dmarc, dkim, mta_sts, bimi)

        return EmailSecurityResult(
            domain=domain,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            mta_sts=mta_sts,
            bimi=bimi,
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
        answers = dns.resolver.resolve(f"{rev}.origin.asn.cymru.com", "TXT", lifetime=DNS_LIFETIME)
        return b"".join(answers[0].strings).decode("utf-8", errors="replace")
    except Exception:
        return None


def _cymru_asn_lookup(asn_num: int) -> str | None:
    """AS-number Cymru DNS TXT → 'ASN | CC | Registry | Date | Name, CC'."""
    try:
        answers = dns.resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT", lifetime=DNS_LIFETIME)
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
    domain: str, a_records: list[str], *, timeout: int = PASSIVE_TIMEOUT,
) -> IPEnrichmentResult:
    """Enrich A records with ASN/hosting/country info via Team Cymru DNS.

    Two TXT lookups per unique IP (origin + ASN name), run concurrently.
    No traffic reaches the target — all queries go to Cymru's resolvers.
    """
    if not a_records:
        return IPEnrichmentResult(domain=domain)

    try:
        origin_tasks = [
            _bounded_executor(_cymru_origin_lookup, ip)
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
            _bounded_executor(_cymru_asn_lookup, asn)
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
