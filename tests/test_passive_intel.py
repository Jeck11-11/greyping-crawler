"""Tests for passive intel sources (no network — httpx is mocked)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.passive_intel import (
    _format_wayback_ts,
    _rdap_event_date,
    _rdap_nameservers,
    _rdap_registrar,
    query_ct_logs,
    query_dns,
    query_rdap,
    query_wayback,
)


def _fake_response(*, status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_data)
    resp.text = text
    return resp


def _patch_client(fake_resp):
    """Make `httpx.AsyncClient(...)` yield a client whose .get() returns fake_resp."""
    client = MagicMock()
    client.get = AsyncMock(return_value=fake_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_dns_resolves_a_and_aaaa():
    fake_a = [(2, 1, 6, "", ("93.184.216.34", 0))]
    fake_aaaa = [(10, 1, 6, "", ("2606:2800:220:1::248", 0, 0, 0))]

    def _fake_getaddrinfo(host, port, family, socktype):
        import socket
        if family == socket.AF_INET:
            return fake_a
        return fake_aaaa

    with patch("src.passive_intel.socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        result = await query_dns("example.com")

    assert result.domain == "example.com"
    assert len(result.a_records) == 1
    assert result.a_records[0].address == "93.184.216.34"
    assert len(result.aaaa_records) == 1
    assert result.aaaa_records[0].address == "2606:2800:220:1::248"
    assert result.error is None


@pytest.mark.asyncio
async def test_query_dns_handles_nxdomain():
    import socket
    with patch(
        "src.passive_intel.socket.getaddrinfo",
        side_effect=socket.gaierror("NXDOMAIN"),
    ):
        result = await query_dns("nonexistent.invalid")
    assert result.a_records == []
    assert result.aaaa_records == []
    assert result.error is None  # gaierror → empty lists, not an error


# ---------------------------------------------------------------------------
# CT logs (crt.sh)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_ct_logs_dedupes_subdomains_and_collects_issuers():
    fake_data = [
        {
            "name_value": "*.example.com\nexample.com\napi.example.com",
            "common_name": "example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        },
        {
            "name_value": "api.example.com\nadmin.example.com",
            "common_name": "admin.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",  # dupe
        },
        {
            "name_value": "staging.example.com",
            "common_name": "staging.example.com",
            "issuer_name": "C=BE, O=GlobalSign, CN=GlobalSign RSA OV SSL CA 2018",
        },
    ]

    client = _patch_client(_fake_response(json_data=fake_data))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_ct_logs("example.com")

    assert result.domain == "example.com"
    assert "example.com" in result.subdomains
    assert "api.example.com" in result.subdomains
    assert "admin.example.com" in result.subdomains
    assert "staging.example.com" in result.subdomains
    # Issuers deduped
    assert len(result.issuers) == 2
    assert result.certificates_seen == 3


@pytest.mark.asyncio
async def test_query_ct_logs_handles_http_error():
    client = _patch_client(_fake_response(status_code=500, json_data=None))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_ct_logs("example.com")
    assert "500" in (result.error or "")
    assert result.subdomains == []


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------

def test_rdap_event_date_picks_registration():
    events = [
        {"eventAction": "last changed", "eventDate": "2024-01-01"},
        {"eventAction": "registration", "eventDate": "2000-08-14"},
        {"eventAction": "expiration", "eventDate": "2030-08-14"},
    ]
    assert _rdap_event_date(events, "registration") == "2000-08-14"
    assert _rdap_event_date(events, "expiration") == "2030-08-14"
    assert _rdap_event_date(events, "missing") == ""


def test_rdap_registrar_extracts_fn_from_vcard():
    entities = [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrar Inc."],
                ],
            ],
        }
    ]
    assert _rdap_registrar(entities) == "Example Registrar Inc."


def test_rdap_nameservers_lowercases_and_dedupes():
    ns = [
        {"ldhName": "A.IANA-SERVERS.NET"},
        {"ldhName": "b.iana-servers.net"},
        {"ldhName": "A.IANA-SERVERS.NET"},  # dupe
    ]
    assert _rdap_nameservers(ns) == ["a.iana-servers.net", "b.iana-servers.net"]


@pytest.mark.asyncio
async def test_query_rdap_parses_full_response():
    data = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "MarkMonitor Inc."]],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14"},
            {"eventAction": "expiration", "eventDate": "2030-08-14"},
        ],
        "nameservers": [
            {"ldhName": "a.iana-servers.net"},
            {"ldhName": "b.iana-servers.net"},
        ],
        "status": ["client delete prohibited", "client transfer prohibited"],
    }
    client = _patch_client(_fake_response(json_data=data))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_rdap("example.com")

    assert result.registrar == "MarkMonitor Inc."
    assert result.created == "1995-08-14"
    assert result.expires == "2030-08-14"
    assert "a.iana-servers.net" in result.name_servers
    assert "client transfer prohibited" in result.status


@pytest.mark.asyncio
async def test_query_rdap_404_sets_error():
    client = _patch_client(_fake_response(status_code=404, json_data={}))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_rdap("nonexistent.invalid")
    assert "not found" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Wayback
# ---------------------------------------------------------------------------

def test_format_wayback_ts():
    assert _format_wayback_ts("20240115120000") == "2024-01-15"
    assert _format_wayback_ts("weird") == "weird"


@pytest.mark.asyncio
async def test_query_wayback_parses_cdx_rows():
    rows = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["com,example)/", "20010101000000", "http://example.com/", "text/html", "200", "A", "100"],
        ["com,example)/", "20200101000000", "http://example.com/", "text/html", "200", "B", "100"],
        ["com,example)/", "20240101000000", "http://example.com/", "text/html", "200", "C", "100"],
    ]
    client = _patch_client(_fake_response(json_data=rows))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_wayback("example.com")

    assert result.snapshot_count == 3
    assert result.first_seen == "2001-01-01"
    assert result.last_seen == "2024-01-01"
    assert len(result.recent_snapshots) == 3
    assert all("web.archive.org/web/" in s for s in result.recent_snapshots)


@pytest.mark.asyncio
async def test_query_wayback_handles_empty():
    client = _patch_client(_fake_response(json_data=[]))
    with patch("src.passive_intel.httpx.AsyncClient", return_value=client):
        result = await query_wayback("example.com")
    assert result.snapshot_count == 0
    assert result.recent_snapshots == []
