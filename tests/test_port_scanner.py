"""Tests for the TCP port scanner module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import DomainResult, OpenPort, PortScanResult
from src.port_scanner import _RISKY_PORTS, _TOP_PORTS, scan_ports


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_reader(banner: bytes = b"") -> AsyncMock:
    """Create a mock asyncio.StreamReader that returns *banner* on read."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=banner)
    return reader


def _make_writer() -> MagicMock:
    """Create a mock asyncio.StreamWriter with close/wait_closed."""
    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return writer


# ---------------------------------------------------------------------------
# Unit tests — scan_ports
# ---------------------------------------------------------------------------

class TestScanPortsOpenPorts:
    @pytest.mark.asyncio
    async def test_detects_open_ports(self):
        """Open ports are reported with correct service names."""
        open_set = {80, 443}

        async def mock_open_connection(host, port):
            if port in open_set:
                return _make_reader(), _make_writer()
            raise OSError("Connection refused")

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("93.184.216.34", 0)),
             ]):
            result = await scan_ports("example.com", ports=_TOP_PORTS, timeout=1)

        assert result.error is None
        assert result.ip == "93.184.216.34"
        assert result.ports_scanned == len(_TOP_PORTS)
        assert result.scan_duration_seconds > 0

        port_numbers = {p.port for p in result.open_ports}
        assert port_numbers == {80, 443}

        http = next(p for p in result.open_ports if p.port == 80)
        assert http.service == "HTTP"
        assert http.is_risky is False

        https = next(p for p in result.open_ports if p.port == 443)
        assert https.service == "HTTPS"
        assert https.is_risky is False

    @pytest.mark.asyncio
    async def test_no_open_ports(self):
        """All connections refused yields empty open_ports."""
        async def mock_open_connection(host, port):
            raise OSError("Connection refused")

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("1.2.3.4", 0)),
             ]):
            result = await scan_ports("closed.example.com", ports={80: "HTTP", 443: "HTTPS"})

        assert result.open_ports == []
        assert result.ports_scanned == 2
        assert result.error is None


class TestRiskyPorts:
    @pytest.mark.asyncio
    async def test_risky_ports_flagged(self):
        """Ports in _RISKY_PORTS get is_risky=True."""
        test_ports = {3306: "MySQL", 6379: "Redis", 80: "HTTP"}

        async def mock_open_connection(host, port):
            return _make_reader(), _make_writer()

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("10.0.0.1", 0)),
             ]):
            result = await scan_ports("db.example.com", ports=test_ports, timeout=1)

        assert len(result.open_ports) == 3

        mysql = next(p for p in result.open_ports if p.port == 3306)
        assert mysql.is_risky is True
        assert mysql.service == "MySQL"

        redis = next(p for p in result.open_ports if p.port == 6379)
        assert redis.is_risky is True

        http = next(p for p in result.open_ports if p.port == 80)
        assert http.is_risky is False

    def test_risky_ports_constant(self):
        """All _RISKY_PORTS are present in _TOP_PORTS."""
        assert _RISKY_PORTS.issubset(_TOP_PORTS.keys())


class TestBannerGrab:
    @pytest.mark.asyncio
    async def test_banner_captured(self):
        """Banner data is recorded on open ports."""
        banner_text = b"SSH-2.0-OpenSSH_8.9\r\n"

        async def mock_open_connection(host, port):
            return _make_reader(banner_text), _make_writer()

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("10.0.0.1", 0)),
             ]):
            result = await scan_ports("ssh.example.com", ports={22: "SSH"}, timeout=1)

        assert len(result.open_ports) == 1
        assert result.open_ports[0].banner == "SSH-2.0-OpenSSH_8.9"

    @pytest.mark.asyncio
    async def test_banner_empty_when_no_data(self):
        """Ports that send no banner data get an empty banner string."""
        async def mock_open_connection(host, port):
            return _make_reader(b""), _make_writer()

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("10.0.0.1", 0)),
             ]):
            result = await scan_ports("web.example.com", ports={80: "HTTP"}, timeout=1)

        assert len(result.open_ports) == 1
        assert result.open_ports[0].banner == ""

    @pytest.mark.asyncio
    async def test_banner_timeout_still_reports_open(self):
        """If banner read times out, port is still reported as open."""
        async def mock_open_connection(host, port):
            reader = AsyncMock()
            reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
            return reader, _make_writer()

        import asyncio
        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("10.0.0.1", 0)),
             ]):
            result = await scan_ports("web.example.com", ports={443: "HTTPS"}, timeout=1)

        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 443
        assert result.open_ports[0].banner == ""


class TestTimeoutHandling:
    @pytest.mark.asyncio
    async def test_connection_timeout_treated_as_closed(self):
        """Ports that time out on connect are not reported as open."""
        import asyncio

        async def mock_open_connection(host, port):
            raise asyncio.TimeoutError()

        with patch("src.port_scanner.asyncio.open_connection", side_effect=mock_open_connection), \
             patch("src.port_scanner.socket.getaddrinfo", return_value=[
                 (2, 1, 6, "", ("10.0.0.1", 0)),
             ]):
            result = await scan_ports("slow.example.com", ports={80: "HTTP"}, timeout=1)

        assert result.open_ports == []
        assert result.error is None


class TestDNSResolution:
    @pytest.mark.asyncio
    async def test_dns_resolution_failure(self):
        """Unresolvable hostname returns an error result."""
        import socket

        with patch("src.port_scanner.socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            result = await scan_ports("nonexistent.invalid")

        assert result.error is not None
        assert "nonexistent.invalid" in result.error
        assert result.open_ports == []
        assert result.ip == ""

    @pytest.mark.asyncio
    async def test_empty_getaddrinfo_result(self):
        """Empty getaddrinfo result is treated as a resolution failure."""
        with patch("src.port_scanner.socket.getaddrinfo", return_value=[]):
            result = await scan_ports("empty.example.com")

        assert result.error is not None
        assert "Could not resolve" in result.error


# ---------------------------------------------------------------------------

