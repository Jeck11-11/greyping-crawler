"""Tests for the cloud asset discovery module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cloud_assets import (
    _BUCKET_SUFFIXES,
    _PROVIDERS,
    _classify_response,
    _generate_candidates,
    discover_cloud_assets,
)
from src.fair_signals import compute_fair_signals
from src.models import (
    CloudAssetFinding,
    CloudAssetResult,
    DomainResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(body: str, status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response with the given body text."""
    resp = MagicMock()
    resp.text = body
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------
# Bucket name generation
# ---------------------------------------------------------------------------

class TestGenerateCandidates:
    def test_basic_domain(self):
        candidates = _generate_candidates("example.com")
        # Should include full domain (dots→hyphens) and without TLD
        assert "example-com" in candidates
        assert "example" in candidates

    def test_suffixes_applied(self):
        candidates = _generate_candidates("example.com")
        # Check a few suffixes are applied to both bases
        assert "example-com-assets" in candidates
        assert "example-assets" in candidates
        assert "example-com-backup" in candidates
        assert "example-backup" in candidates
        assert "example-com-static" in candidates
        assert "example-static" in candidates

    def test_all_suffixes_present(self):
        candidates = _generate_candidates("example.com")
        for suffix in _BUCKET_SUFFIXES:
            assert f"example{suffix}" in candidates

    def test_protocol_stripped(self):
        candidates = _generate_candidates("https://example.com")
        assert "example-com" in candidates
        assert "example" in candidates
        # No https:// artifacts
        assert all("https" not in c for c in candidates)

    def test_path_stripped(self):
        candidates = _generate_candidates("example.com/some/path")
        assert "example-com" in candidates
        assert "example" in candidates

    def test_port_stripped(self):
        candidates = _generate_candidates("example.com:8080")
        assert "example-com" in candidates
        assert "example" in candidates

    def test_uppercase_lowered(self):
        candidates = _generate_candidates("EXAMPLE.COM")
        assert "example-com" in candidates
        assert "example" in candidates

    def test_subdomain_handling(self):
        candidates = _generate_candidates("sub.example.com")
        # Full domain with dots→hyphens
        assert "sub-example-com" in candidates
        # Without TLD
        assert "sub-example" in candidates

    def test_no_duplicates(self):
        candidates = _generate_candidates("example.com")
        assert len(candidates) == len(set(candidates))


# ---------------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    # --- AWS S3 ---
    def test_s3_public(self):
        body = '<?xml version="1.0"?><ListBucketResult><Name>test</Name></ListBucketResult>'
        result = _classify_response(body, _PROVIDERS["aws_s3"])
        assert result == "public"

    def test_s3_private(self):
        body = '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'
        result = _classify_response(body, _PROVIDERS["aws_s3"])
        assert result == "exists_private"

    def test_s3_not_found(self):
        body = '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>'
        result = _classify_response(body, _PROVIDERS["aws_s3"])
        assert result is None

    def test_s3_all_access_disabled(self):
        body = '<Error><Code>AllAccessDisabled</Code></Error>'
        result = _classify_response(body, _PROVIDERS["aws_s3"])
        assert result == "exists_private"

    # --- Azure Blob ---
    def test_azure_public(self):
        body = '<?xml version="1.0"?><EnumerationResults><Blobs></Blobs></EnumerationResults>'
        result = _classify_response(body, _PROVIDERS["azure_blob"])
        assert result == "public"

    def test_azure_private(self):
        body = '<Error><Code>AuthenticationFailed</Code></Error>'
        result = _classify_response(body, _PROVIDERS["azure_blob"])
        assert result == "exists_private"

    def test_azure_private_auth_failure(self):
        body = 'Server failed to authenticate the request.'
        result = _classify_response(body, _PROVIDERS["azure_blob"])
        assert result == "exists_private"

    def test_azure_not_found(self):
        body = '<Error><Code>ContainerNotFound</Code></Error>'
        result = _classify_response(body, _PROVIDERS["azure_blob"])
        assert result is None

    def test_azure_not_found_out_of_range(self):
        body = '<Error><Code>OutOfRangeInput</Code></Error>'
        result = _classify_response(body, _PROVIDERS["azure_blob"])
        assert result is None

    # --- GCS ---
    def test_gcs_public_list(self):
        body = '<?xml version="1.0"?><ListBucketResult><Name>test</Name></ListBucketResult>'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result == "public"

    def test_gcs_public_contents(self):
        body = '<Contents><Key>file.txt</Key></Contents>'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result == "public"

    def test_gcs_private(self):
        body = '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result == "exists_private"

    def test_gcs_private_lowercase(self):
        body = 'Access denied. You do not have permission.'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result == "exists_private"

    def test_gcs_not_found(self):
        body = '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result is None

    def test_gcs_not_found_plain(self):
        body = 'Not Found'
        result = _classify_response(body, _PROVIDERS["gcs"])
        assert result is None

    # --- Unrecognised ---
    def test_unrecognised_response(self):
        body = '<html><body>Something unexpected</body></html>'
        result = _classify_response(body, _PROVIDERS["aws_s3"])
        assert result is None


# ---------------------------------------------------------------------------
# discover_cloud_assets — integration with mocked httpx
# ---------------------------------------------------------------------------

class TestDiscoverCloudAssetsS3:
    @pytest.mark.asyncio
    async def test_s3_bucket_public(self):
        """A public S3 bucket is detected and included in findings."""
        s3_public_body = '<?xml version="1.0"?><ListBucketResult><Name>example</Name></ListBucketResult>'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "s3.amazonaws.com" in url and "example.s3" in url:
                resp.text = s3_public_body
            else:
                resp.text = '<Error><Code>NoSuchBucket</Code></Error>'
            resp.status_code = 200
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        assert isinstance(result, CloudAssetResult)
        assert result.domain == "example.com"
        assert result.buckets_checked > 0
        assert result.scan_duration_seconds >= 0
        assert result.error is None

        public_findings = [f for f in result.findings if f.status == "public"]
        assert len(public_findings) >= 1
        s3_public = [f for f in public_findings if f.provider == "aws_s3"]
        assert len(s3_public) >= 1
        assert s3_public[0].severity == "critical"
        assert "ListBucketResult" in s3_public[0].evidence

    @pytest.mark.asyncio
    async def test_s3_bucket_private(self):
        """A private S3 bucket is detected with exists_private status."""
        s3_private_body = '<Error><Code>AccessDenied</Code></Error>'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "s3.amazonaws.com" in url and "example.s3" in url:
                resp.text = s3_private_body
            else:
                resp.text = '<Error><Code>NoSuchBucket</Code></Error>'
            resp.status_code = 403
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        private_findings = [f for f in result.findings if f.status == "exists_private"]
        assert len(private_findings) >= 1
        s3_private = [f for f in private_findings if f.provider == "aws_s3"]
        assert len(s3_private) >= 1
        assert s3_private[0].severity == "high"
        assert "AccessDenied" in s3_private[0].evidence

    @pytest.mark.asyncio
    async def test_s3_bucket_not_found(self):
        """Non-existent S3 buckets are not included in findings."""
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = '<Error><Code>NoSuchBucket</Code></Error>'
            resp.status_code = 404
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        assert result.findings == []
        assert result.buckets_checked > 0


class TestDiscoverCloudAssetsAzure:
    @pytest.mark.asyncio
    async def test_azure_blob_public(self):
        """A public Azure blob container is detected."""
        azure_public_body = '<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>data.csv</Name></Blob></Blobs></EnumerationResults>'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "blob.core.windows.net" in url and "example.blob" in url:
                resp.text = azure_public_body
            else:
                resp.text = 'Not Found'
            resp.status_code = 200
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        azure_public = [f for f in result.findings if f.provider == "azure_blob" and f.status == "public"]
        assert len(azure_public) >= 1
        assert azure_public[0].severity == "critical"
        assert "EnumerationResults" in azure_public[0].evidence

    @pytest.mark.asyncio
    async def test_azure_blob_private(self):
        """A private Azure blob container is detected."""
        azure_private_body = 'Server failed to authenticate the request.'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "blob.core.windows.net" in url and "example.blob" in url:
                resp.text = azure_private_body
            else:
                resp.text = 'Not Found'
            resp.status_code = 403
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        azure_private = [f for f in result.findings if f.provider == "azure_blob" and f.status == "exists_private"]
        assert len(azure_private) >= 1
        assert azure_private[0].severity == "high"

    @pytest.mark.asyncio
    async def test_azure_blob_not_found(self):
        """Non-existent Azure blob containers are not included."""
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = '<Error><Code>ContainerNotFound</Code></Error>'
            resp.status_code = 404
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        azure_findings = [f for f in result.findings if f.provider == "azure_blob"]
        assert azure_findings == []


class TestDiscoverCloudAssetsGCS:
    @pytest.mark.asyncio
    async def test_gcs_bucket_public(self):
        """A public GCS bucket is detected."""
        gcs_public_body = '<?xml version="1.0"?><ListBucketResult><Name>example</Name><Contents><Key>file.txt</Key></Contents></ListBucketResult>'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "storage.googleapis.com" in url and "/example/" in url:
                resp.text = gcs_public_body
            else:
                resp.text = 'Not Found'
            resp.status_code = 200
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        gcs_public = [f for f in result.findings if f.provider == "gcs" and f.status == "public"]
        assert len(gcs_public) >= 1
        assert gcs_public[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_gcs_bucket_private(self):
        """A private GCS bucket is detected."""
        gcs_private_body = '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "storage.googleapis.com" in url and "/example/" in url:
                resp.text = gcs_private_body
            else:
                resp.text = 'Not Found'
            resp.status_code = 403
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        gcs_private = [f for f in result.findings if f.provider == "gcs" and f.status == "exists_private"]
        assert len(gcs_private) >= 1
        assert gcs_private[0].severity == "high"

    @pytest.mark.asyncio
    async def test_gcs_bucket_not_found(self):
        """Non-existent GCS buckets are not included."""
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = 'Not Found'
            resp.status_code = 404
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        gcs_findings = [f for f in result.findings if f.provider == "gcs"]
        assert gcs_findings == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestDiscoverCloudAssetsErrorHandling:
    @pytest.mark.asyncio
    async def test_http_exception_handled(self):
        """HTTP exceptions during probes are handled gracefully."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection error"))

        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        # Should complete without raising, with no findings
        assert isinstance(result, CloudAssetResult)
        assert result.findings == []
        assert result.buckets_checked > 0

    @pytest.mark.asyncio
    async def test_client_creation_failure(self):
        """Client creation failure returns error result."""
        with patch("src.cloud_assets.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                side_effect=Exception("Failed to create client")
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await discover_cloud_assets("example.com", concurrency=5)

        assert result.error is not None
        assert result.domain == "example.com"


# ---------------------------------------------------------------------------
# FAIR signal integration
# ---------------------------------------------------------------------------

class TestFAIRExposedCloudStorage:
    def test_public_cloud_bucket_fires_signal(self):
        """Public cloud bucket findings produce an exposed_cloud_storage FAIR signal."""
        result = DomainResult(
            target="https://example.com",
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[
                    CloudAssetFinding(
                        bucket_name="example",
                        provider="aws_s3",
                        url="https://example.s3.amazonaws.com/",
                        status="public",
                        evidence=["ListBucketResult"],
                        severity="critical",
                    ),
                ],
                buckets_checked=108,
                scan_duration_seconds=5.0,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")

        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "exposed_cloud_storage" in vuln_names

        sig = next(s for s in signals.vulnerability.signals if s.name == "exposed_cloud_storage")
        # 1 public bucket: score = min(100, 70 + 10 * 1) = 80
        assert sig.score == 80
        assert sig.weight == 1.4
        assert any("aws_s3" in e for e in sig.evidence)

    def test_multiple_public_buckets_increase_score(self):
        """Multiple public buckets produce a higher score."""
        result = DomainResult(
            target="https://example.com",
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[
                    CloudAssetFinding(
                        bucket_name="example",
                        provider="aws_s3",
                        url="https://example.s3.amazonaws.com/",
                        status="public",
                        evidence=["ListBucketResult"],
                        severity="critical",
                    ),
                    CloudAssetFinding(
                        bucket_name="example-backup",
                        provider="gcs",
                        url="https://storage.googleapis.com/example-backup/",
                        status="public",
                        evidence=["ListBucketResult"],
                        severity="critical",
                    ),
                    CloudAssetFinding(
                        bucket_name="example-data",
                        provider="azure_blob",
                        url="https://example-data.blob.core.windows.net/?comp=list",
                        status="public",
                        evidence=["EnumerationResults"],
                        severity="critical",
                    ),
                ],
                buckets_checked=108,
                scan_duration_seconds=5.0,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")

        sig = next(s for s in signals.vulnerability.signals if s.name == "exposed_cloud_storage")
        # 3 public buckets: score = min(100, 70 + 10 * 3) = 100
        assert sig.score == 100

    def test_private_only_no_signal(self):
        """Private-only cloud findings do not produce exposed_cloud_storage signal."""
        result = DomainResult(
            target="https://example.com",
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[
                    CloudAssetFinding(
                        bucket_name="example",
                        provider="aws_s3",
                        url="https://example.s3.amazonaws.com/",
                        status="exists_private",
                        evidence=["AccessDenied"],
                        severity="high",
                    ),
                ],
                buckets_checked=108,
                scan_duration_seconds=5.0,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")

        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "exposed_cloud_storage" not in vuln_names

    def test_no_cloud_assets_no_signal(self):
        """Without cloud_assets data, exposed_cloud_storage signal is absent."""
        result = DomainResult(target="https://example.com")
        signals = compute_fair_signals(result, scan_mode="full")

        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "exposed_cloud_storage" not in vuln_names

    def test_empty_findings_no_signal(self):
        """Cloud scan with zero findings does not fire the signal."""
        result = DomainResult(
            target="https://example.com",
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[],
                buckets_checked=108,
                scan_duration_seconds=2.0,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")

        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "exposed_cloud_storage" not in vuln_names

    def test_public_bucket_increases_overall_risk(self):
        """Public cloud buckets push overall risk higher than a bare result."""
        bare = DomainResult(target="https://example.com")
        bare_signals = compute_fair_signals(bare, scan_mode="full")

        with_bucket = DomainResult(
            target="https://example.com",
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[
                    CloudAssetFinding(
                        bucket_name="example",
                        provider="aws_s3",
                        url="https://example.s3.amazonaws.com/",
                        status="public",
                        evidence=["ListBucketResult"],
                        severity="critical",
                    ),
                ],
                buckets_checked=108,
                scan_duration_seconds=5.0,
            ),
        )
        bucket_signals = compute_fair_signals(with_bucket, scan_mode="full")

        assert bucket_signals.vulnerability.score > bare_signals.vulnerability.score
