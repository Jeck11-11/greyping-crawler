"""Tests for the 7 new DNS record types (TLSA, SSHFP, DS, NAPTR, LOC, RP, HINFO)."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from src.passive_intel import (
    _resolve_tlsa,
    _resolve_sshfp,
    _resolve_ds,
    _resolve_naptr,
    _resolve_loc,
    _resolve_rp,
    _resolve_hinfo,
    query_dns,
)


def _mock_rrset(records, ttl=300):
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter(records))
    rrset = MagicMock()
    rrset.ttl = ttl
    answer.rrset = rrset
    return answer


class TestResolveTLSA:
    def test_parses_multiple_ports(self):
        rr443 = SimpleNamespace(usage=3, selector=1, mtype=1, cert=b"\xab\xcd")
        rr25 = SimpleNamespace(usage=2, selector=0, mtype=2, cert=b"\x01\x02\x03")

        def fake_resolve(name, rdtype, lifetime=None):
            if name == "_443._tcp.example.com":
                return _mock_rrset([rr443], ttl=3600)
            if name == "_25._tcp.example.com":
                return _mock_rrset([rr25], ttl=600)
            raise dns.resolver.NXDOMAIN()

        with patch("src.passive_intel.dns.resolver.resolve", side_effect=fake_resolve):
            records = _resolve_tlsa("example.com")

        assert len(records) == 2
        r443 = next(r for r in records if r.port == 443)
        assert r443.usage == 3
        assert r443.selector == 1
        assert r443.matching_type == 1
        assert r443.certificate_data == "abcd"
        assert r443.protocol == "tcp"
        assert r443.ttl == 3600

        r25 = next(r for r in records if r.port == 25)
        assert r25.usage == 2
        assert r25.certificate_data == "010203"

    def test_handles_no_records(self):
        with patch("src.passive_intel.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            records = _resolve_tlsa("example.com")
        assert records == []


class TestResolveSSHFP:
    def test_parses_record(self):
        rr = SimpleNamespace(algorithm=4, fp_type=2, fingerprint=b"\xde\xad\xbe\xef")
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_sshfp("example.com")

        assert len(records) == 1
        assert records[0].algorithm == 4
        assert records[0].fingerprint_type == 2
        assert records[0].fingerprint == "deadbeef"
        assert records[0].ttl == 300

    def test_handles_no_records(self):
        with patch("src.passive_intel.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
            assert _resolve_sshfp("example.com") == []


class TestResolveDS:
    def test_parses_record(self):
        rr = SimpleNamespace(key_tag=12345, algorithm=8, digest_type=2, digest=b"\xaa\xbb\xcc")
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_ds("example.com")

        assert len(records) == 1
        assert records[0].key_tag == 12345
        assert records[0].algorithm == 8
        assert records[0].digest_type == 2
        assert records[0].digest == "aabbcc"


class TestResolveNAPTR:
    def test_parses_sip_record(self):
        rr = SimpleNamespace(
            order=10,
            preference=100,
            flags=b"S",
            service=b"SIP+D2U",
            regexp=b"",
            replacement=MagicMock(__str__=lambda self: "sip.example.com."),
        )
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_naptr("example.com")

        assert len(records) == 1
        assert records[0].order == 10
        assert records[0].preference == 100
        assert records[0].flags == "S"
        assert records[0].service == "SIP+D2U"
        assert records[0].replacement == "sip.example.com"


class TestResolveLOC:
    def test_converts_altitude_correctly(self):
        # 100m above sea level = (100 + 100000) * 100 = 10010000 centimeters
        rr = SimpleNamespace(
            float_latitude=51.5074,
            float_longitude=-0.1278,
            altitude=10010000,
            size=100,
            horizontal_precision=1000,
            vertical_precision=1000,
        )
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_loc("example.com")

        assert len(records) == 1
        assert records[0].latitude == pytest.approx(51.5074)
        assert records[0].longitude == pytest.approx(-0.1278)
        assert records[0].altitude == pytest.approx(100.0)
        assert records[0].size == pytest.approx(1.0)


class TestResolveRP:
    def test_converts_mbox_to_email(self):
        rr = SimpleNamespace(
            mbox=MagicMock(__str__=lambda self: "admin.example.com."),
            txt=MagicMock(__str__=lambda self: "info.example.com."),
        )
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_rp("example.com")

        assert len(records) == 1
        assert records[0].mbox == "admin@example.com"
        assert records[0].txt_domain == "info.example.com"


class TestResolveHINFO:
    def test_decodes_bytes(self):
        rr = SimpleNamespace(cpu=b"Intel Xeon", os=b"Linux 5.15")
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_hinfo("example.com")

        assert len(records) == 1
        assert records[0].cpu == "Intel Xeon"
        assert records[0].os == "Linux 5.15"

    def test_handles_string_fields(self):
        rr = SimpleNamespace(cpu="AMD EPYC", os="FreeBSD")
        with patch("src.passive_intel.dns.resolver.resolve", return_value=_mock_rrset([rr])):
            records = _resolve_hinfo("example.com")

        assert records[0].cpu == "AMD EPYC"
        assert records[0].os == "FreeBSD"


class TestQueryDNSIncludesNewRecords:
    @pytest.mark.asyncio
    async def test_new_fields_on_dns_result(self):
        """query_dns returns DNSResult with all 7 new record type fields."""
        import socket

        def _fake_getaddrinfo(host, port, family, socktype):
            if family == socket.AF_INET:
                return [(2, 1, 6, "", ("1.2.3.4", 0))]
            return []

        with patch("src.passive_intel.socket.getaddrinfo", side_effect=_fake_getaddrinfo):
            result = await query_dns("example.com")

        assert hasattr(result, "tlsa_records")
        assert hasattr(result, "sshfp_records")
        assert hasattr(result, "ds_records")
        assert hasattr(result, "naptr_records")
        assert hasattr(result, "loc_records")
        assert hasattr(result, "rp_records")
        assert hasattr(result, "hinfo_records")
        assert isinstance(result.tlsa_records, list)
        assert isinstance(result.sshfp_records, list)
        assert result.error is None
