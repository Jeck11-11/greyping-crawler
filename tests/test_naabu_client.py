"""Tests for the naabu port scanner client and port_scanner augmentation."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.models import NaabuPort, NaabuScanResult, OpenPort, PortScanResult
from src.port_scanner import _naabu_to_port_scan_result, scan_ports


class TestNaabuToPortScanResult:
    def test_maps_known_ports(self):
        naabu = NaabuScanResult(
            target="example.com",
            ports=[
                NaabuPort(host="example.com", ip="93.184.216.34", port=80, protocol="tcp"),
                NaabuPort(host="example.com", ip="93.184.216.34", port=443, protocol="tcp"),
            ],
        )
        result = _naabu_to_port_scan_result("example.com", naabu)
        assert isinstance(result, PortScanResult)
        assert result.target == "example.com"
        assert result.ip == "93.184.216.34"
        assert len(result.open_ports) == 2
        assert result.open_ports[0].port == 80
        assert result.open_ports[0].service == "HTTP"
        assert result.open_ports[1].port == 443
        assert result.open_ports[1].service == "HTTPS"

    def test_flags_risky_ports(self):
        naabu = NaabuScanResult(
            target="example.com",
            ports=[
                NaabuPort(host="example.com", ip="1.2.3.4", port=3306),
                NaabuPort(host="example.com", ip="1.2.3.4", port=6379),
                NaabuPort(host="example.com", ip="1.2.3.4", port=80),
            ],
        )
        result = _naabu_to_port_scan_result("example.com", naabu)
        mysql = next(p for p in result.open_ports if p.port == 3306)
        redis = next(p for p in result.open_ports if p.port == 6379)
        http = next(p for p in result.open_ports if p.port == 80)
        assert mysql.is_risky is True
        assert redis.is_risky is True
        assert http.is_risky is False

    def test_unknown_port_gets_unknown_service(self):
        naabu = NaabuScanResult(
            target="example.com",
            ports=[NaabuPort(host="example.com", ip="1.2.3.4", port=59999)],
        )
        result = _naabu_to_port_scan_result("example.com", naabu)
        assert result.open_ports[0].service == "unknown"

    def test_sorted_by_port(self):
        naabu = NaabuScanResult(
            target="example.com",
            ports=[
                NaabuPort(host="example.com", port=8080),
                NaabuPort(host="example.com", port=22),
                NaabuPort(host="example.com", port=443),
            ],
        )
        result = _naabu_to_port_scan_result("example.com", naabu)
        assert [p.port for p in result.open_ports] == [22, 443, 8080]

    def test_empty_ports(self):
        naabu = NaabuScanResult(target="example.com", ports=[])
        result = _naabu_to_port_scan_result("example.com", naabu)
        assert result.open_ports == []


class TestNaabuClientParsing:
    def test_parse_jsonl(self):
        from src.naabu_client import _parse_naabu_jsonl

        text = '{"host":"example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}\n{"host":"example.com","ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
        ports = _parse_naabu_jsonl(text)
        assert len(ports) == 2
        assert ports[0].port == 80
        assert ports[1].port == 443

    def test_parse_jsonl_skips_bad_lines(self):
        from src.naabu_client import _parse_naabu_jsonl

        text = 'not json\n{"host":"x","port":22}\n'
        ports = _parse_naabu_jsonl(text)
        assert len(ports) == 1
        assert ports[0].port == 22


class TestScanPortsFallback:
    @patch("src.port_scanner.PD_TOOLS_API_URL", "")
    @pytest.mark.asyncio
    async def test_uses_python_when_no_pd_url(self):
        with patch("src.port_scanner._scan_ports_python", new_callable=AsyncMock) as mock_python:
            mock_python.return_value = PortScanResult(target="example.com")
            result = await scan_ports("example.com")
            mock_python.assert_called_once()

    @patch("src.port_scanner.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_uses_naabu_when_pd_url_set(self):
        naabu_result = NaabuScanResult(
            target="example.com",
            ports=[NaabuPort(host="example.com", ip="1.2.3.4", port=80)],
        )
        with patch("src.naabu_client.run_naabu_scan", new_callable=AsyncMock, return_value=naabu_result) as mock_naabu:
            result = await scan_ports("example.com")
            mock_naabu.assert_called_once()
            assert len(result.open_ports) == 1
            assert result.open_ports[0].port == 80

    @patch("src.port_scanner.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_falls_back_on_naabu_error(self):
        naabu_result = NaabuScanResult(target="example.com", error="connection refused")
        with patch("src.naabu_client.run_naabu_scan", new_callable=AsyncMock, return_value=naabu_result):
            with patch("src.port_scanner._scan_ports_python", new_callable=AsyncMock) as mock_python:
                mock_python.return_value = PortScanResult(target="example.com")
                result = await scan_ports("example.com")
                mock_python.assert_called_once()

    @patch("src.port_scanner.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_falls_back_on_naabu_exception(self):
        with patch("src.naabu_client.run_naabu_scan", new_callable=AsyncMock, side_effect=RuntimeError("crash")):
            with patch("src.port_scanner._scan_ports_python", new_callable=AsyncMock) as mock_python:
                mock_python.return_value = PortScanResult(target="example.com")
                result = await scan_ports("example.com")
                mock_python.assert_called_once()
