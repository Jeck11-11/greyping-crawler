"""Tests for /recon/crawl, /recon/contacts, /recon/links, /recon/secrets, /recon/ioc."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import (
    ContactInfo,
    IoCFinding,
    LinkInfo,
    PageResult,
    SecretFinding,
)


client = TestClient(app)


def _sample_pages() -> list[PageResult]:
    return [
        PageResult(
            url="https://example.com",
            status_code=200,
            title="Home",
            contacts=ContactInfo(
                emails=["a@example.com"],
                phone_numbers=["+15551234567"],
                social_profiles=["https://twitter.com/example"],
            ),
            links=[
                LinkInfo(url="https://example.com/about", link_type="internal"),
                LinkInfo(
                    url="https://partner.com/",
                    anchor_text="Partner",
                    link_type="external",
                ),
            ],
            secrets=[
                SecretFinding(
                    secret_type="aws_access_key",
                    matched_pattern="aws",
                    value_preview="AKIA****KEY1",
                    location="script",
                    severity="high",
                ),
            ],
            ioc_findings=[
                IoCFinding(
                    ioc_type="cryptominer",
                    description="CoinHive-like script",
                    evidence="coinhive.min.js",
                    location="script",
                    severity="high",
                ),
            ],
        ),
        PageResult(
            url="https://example.com/about",
            status_code=200,
            contacts=ContactInfo(emails=["a@example.com"]),  # dupe across pages
            links=[
                LinkInfo(url="https://partner.com/", link_type="external"),
            ],
            ioc_findings=[
                IoCFinding(
                    ioc_type="cryptominer",
                    description="CoinHive-like script",
                    evidence="coinhive.min.js",  # dupe across pages
                    location="script",
                    severity="high",
                ),
            ],
        ),
    ]


class TestReconCrawl:
    @patch("src.routers.content.crawl_domain", new_callable=AsyncMock)
    def test_crawl_returns_pages(self, mock_crawl):
        mock_crawl.return_value = _sample_pages()
        resp = client.post(
            "/recon/crawl",
            json={"targets": ["https://example.com"], "max_depth": 1},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["pages_scanned"] == 2
        assert len(body[0]["pages"]) == 2


class TestReconContacts:
    @patch("src.routers.content.crawl_domain", new_callable=AsyncMock)
    def test_contacts_dedupes_and_records_provenance(self, mock_crawl):
        mock_crawl.return_value = _sample_pages()
        resp = client.post(
            "/recon/contacts", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        # single email, but found_on has both pages
        assert len(body["emails"]) == 1
        assert set(body["emails"][0]["found_on"]) == {
            "https://example.com",
            "https://example.com/about",
        }
        # twitter detection
        assert body["social_profiles"][0]["platform"] == "Twitter"


class TestReconLinks:
    @patch("src.routers.content.crawl_domain", new_callable=AsyncMock)
    def test_links_splits_internal_vs_external(self, mock_crawl):
        mock_crawl.return_value = _sample_pages()
        resp = client.post(
            "/recon/links", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert body["internal_links"] == ["https://example.com/about"]
        assert len(body["external_links"]) == 1
        assert body["external_links"][0]["url"] == "https://partner.com/"


class TestReconSecrets:
    @patch("src.routers.content.crawl_domain", new_callable=AsyncMock)
    def test_secrets_aggregated_across_pages(self, mock_crawl):
        mock_crawl.return_value = _sample_pages()
        resp = client.post(
            "/recon/secrets", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert len(body["secrets"]) == 1
        assert body["secrets"][0]["secret_type"] == "aws_access_key"


class TestReconIoC:
    @patch("src.routers.content.crawl_domain", new_callable=AsyncMock)
    def test_ioc_dedupes_identical_evidence(self, mock_crawl):
        mock_crawl.return_value = _sample_pages()
        resp = client.post(
            "/recon/ioc", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        # same (ioc_type, evidence) across two pages => one finding
        assert len(body["ioc_findings"]) == 1
