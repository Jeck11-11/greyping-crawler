"""TCP port scanner with banner grabbing.

Performs async TCP connect scans against a configurable set of well-known
ports, captures service banners when available, and flags risky services
(databases, remote-access tools) that should not be internet-exposed.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time

from .config import PORT_SCAN_CONCURRENCY, PORT_SCAN_TIMEOUT
from .models import OpenPort, PortScanResult

logger = logging.getLogger(__name__)

# Top 21 most-scanned TCP ports and their typical service names.
_TOP_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Ports that should not normally be exposed to the public internet.
_RISKY_PORTS: frozenset[int] = frozenset({23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017})


async def _probe_port(
    ip: str,
    port: int,
    service: str,
    timeout: int,
    semaphore: asyncio.Semaphore,
) -> OpenPort | None:
    """Attempt a TCP connect to *ip*:*port* and optionally grab a banner."""
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, OSError):
            return None

        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, AttributeError):
                pass

        return OpenPort(
            port=port,
            service=service,
            banner=banner,
            is_risky=port in _RISKY_PORTS,
        )


async def scan_ports(
    host: str,
    *,
    ports: dict[int, str] | None = None,
    timeout: int = PORT_SCAN_TIMEOUT,
    concurrency: int = PORT_SCAN_CONCURRENCY,
) -> PortScanResult:
    """Scan *host* for open TCP ports.

    Parameters
    ----------
    host:
        Hostname or IP address to scan.
    ports:
        Mapping of ``{port_number: service_name}`` to scan.  Defaults to
        :data:`_TOP_PORTS` when *None*.
    timeout:
        Per-port connection timeout in seconds.
    concurrency:
        Maximum number of concurrent connection attempts.

    Returns
    -------
    PortScanResult
        Contains the list of open ports, timing info, and any error.
    """
    if ports is None:
        ports = _TOP_PORTS

    # Resolve hostname to IP.
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM),
        )
        if not infos:
            return PortScanResult(
                target=host,
                error=f"Could not resolve hostname: {host}",
            )
        ip = infos[0][4][0]
    except (socket.gaierror, OSError) as exc:
        return PortScanResult(
            target=host,
            error=f"DNS resolution failed for {host}: {exc}",
        )

    semaphore = asyncio.Semaphore(concurrency)
    start = time.monotonic()

    tasks = [
        _probe_port(ip, port, service, timeout, semaphore)
        for port, service in ports.items()
    ]
    results = await asyncio.gather(*tasks)
    duration = time.monotonic() - start

    open_ports = [r for r in results if r is not None]
    open_ports.sort(key=lambda p: p.port)

    return PortScanResult(
        target=host,
        ip=ip,
        open_ports=open_ports,
        ports_scanned=len(ports),
        scan_duration_seconds=round(duration, 3),
    )


__all__ = ["scan_ports", "_TOP_PORTS", "_RISKY_PORTS"]
