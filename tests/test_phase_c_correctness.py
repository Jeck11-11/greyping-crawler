"""Phase C correctness fixes — acceptance tests.

Covers spec Tests 4 (parent-domain DMARC) and 5 (Microsoft autodiscover asset
classification).
"""

from __future__ import annotations

from src.asset_classifier import classify_asset
from src.passive_intel import _organizational_domain
from src.models import (
    CNAMERecord,
    DNSGroup,
    DNSResult,
    DomainResult,
    EmailSecurityResult,
    DMARCResult,
    SecurityGroup,
    SecurityHeadersResult,
)
from src.easm_report import _classify_email_security


def _dns(cnames=None, a=None, mx=None):
    rec = DNSResult(domain="x")
    if cnames:
        rec.cname_records = [CNAMERecord(target=c) for c in cnames]
    return DNSGroup(records=rec)


# --------------------------------------------------------------------------
# Test 5 — Microsoft autodiscover asset classification
# --------------------------------------------------------------------------

class TestAutodiscoverClassification:
    def test_autodiscover_cname_is_autodiscover_service(self):
        result = DomainResult(
            target="https://autodiscover.dnait.ie",
            dns=_dns(cnames=["autodiscover.outlook.com"]),
        )
        asset = classify_asset(result)
        assert asset.asset_type == "autodiscover_service"
        assert asset.provider == "Microsoft 365"
        assert asset.website_checks_applicable is False
        assert asset.privacy_checks_applicable is False
        assert asset.cookie_checks_applicable is False

    def test_apex_website_still_gets_website_checks(self):
        result = DomainResult(
            target="https://dnait.ie",
            security=SecurityGroup(headers=SecurityHeadersResult(grade="C")),
        )
        asset = classify_asset(result)
        assert asset.asset_type == "website"
        assert asset.website_checks_applicable is True


# --------------------------------------------------------------------------
# Test 4 — Parent-domain DMARC applies to subdomains
# --------------------------------------------------------------------------

class TestParentDmarc:
    def test_organizational_domain(self):
        assert _organizational_domain("autodiscover.dnait.ie") == "dnait.ie"
        assert _organizational_domain("dnait.ie") == "dnait.ie"
        assert _organizational_domain("foo.bar.example.co.uk") == "example.co.uk"

    def test_inherited_dmarc_not_flagged_missing(self):
        # A non-mail subdomain whose DMARC is inherited from the parent, and
        # which is not applicable for its own email checks, gets no F.
        es = EmailSecurityResult(
            domain="autodiscover.dnait.ie",
            dmarc=DMARCResult(exists=True, policy="quarantine",
                              inherited_from_parent=True, parent_domain="dnait.ie"),
            is_organizational_domain=False,
            receives_mail=False,
            applicable=False,
            email_security_status="not_applicable",
        )
        result = DomainResult(
            target="https://autodiscover.dnait.ie",
            dns=DNSGroup(records=DNSResult(domain="autodiscover.dnait.ie"),
                         email_security=es),
        )
        findings = _classify_email_security(result)
        assert not any(f.id == "email_no_dmarc" for f in findings)
        assert not any(f.id == "email_no_spf" for f in findings)
        assert not any(f.id == "email_no_mta_sts" for f in findings)
