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

from .config import NAABU_PORT_RANGE, NAABU_TIMEOUT, PD_TOOLS_API_URL, PORT_SCAN_CONCURRENCY, PORT_SCAN_TIMEOUT
from .models import OpenPort, PortScanResult

logger = logging.getLogger(__name__)

# Top 250 most commonly targeted TCP ports and their service names.
_TOP_PORTS: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 49: "TACACS", 53: "DNS", 69: "TFTP", 79: "Finger",
    80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    113: "Ident", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 427: "SLP", 443: "HTTPS",
    445: "SMB", 464: "Kerberos-Pwd", 465: "SMTPS", 500: "ISAKMP",
    502: "Modbus", 512: "rexec", 513: "rlogin", 514: "Syslog",
    515: "LPD", 524: "NCP", 548: "AFP", 554: "RTSP", 563: "NNTPS",
    587: "Submission", 593: "HTTP-RPC", 631: "IPP", 636: "LDAPS",
    873: "Rsync", 888: "HTTP-Alt", 900: "VMware-Auth", 902: "VMware-Auth",
    990: "FTPS", 992: "TelnetS", 993: "IMAPS", 995: "POP3S",
    1025: "NFS-or-IIS", 1080: "SOCKS", 1099: "RMI-Registry",
    1194: "OpenVPN", 1241: "Nessus", 1270: "SCOM", 1337: "waste",
    1344: "ICAP", 1352: "Lotus-Notes", 1433: "MSSQL", 1434: "MSSQL-Monitor",
    1494: "Citrix-ICA", 1521: "Oracle", 1524: "ingreslock",
    1666: "Perforce", 1720: "H.323", 1723: "PPTP", 1755: "MMS",
    1801: "MSMQ", 1812: "RADIUS", 1883: "MQTT", 1900: "UPnP",
    1935: "RTMP", 2000: "Cisco-SCCP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    2121: "FTP-Proxy", 2179: "VMware-RDP", 2222: "SSH-Alt",
    2301: "Compaq-HTTP", 2375: "Docker", 2376: "Docker-TLS",
    2381: "Compaq-HTTPS", 2399: "FileMaker", 2483: "Oracle-DB",
    2484: "Oracle-DB-SSL", 2525: "SMTP-Alt", 2601: "Zebra",
    2638: "Sybase", 3000: "Node/React", 3001: "Grafana",
    3128: "Squid-Proxy", 3260: "iSCSI", 3268: "LDAP-GC",
    3269: "LDAPS-GC", 3283: "Apple-Remote", 3306: "MySQL",
    3333: "dec-notes", 3389: "RDP", 3443: "HTTPS-Alt",
    3478: "STUN", 3500: "RTMP-Alt", 3541: "unknown",
    3542: "unknown", 3632: "distcc", 3689: "DAAP",
    3690: "SVN", 4000: "remoteanything", 4022: "unknown",
    4040: "Spark-UI", 4063: "unknown", 4064: "unknown",
    4111: "xgrid", 4243: "Docker-Alt", 4321: "rwhois",
    4369: "EPMD", 4443: "Pharos", 4444: "Metasploit",
    4445: "upnotifyp", 4505: "SaltStack", 4506: "SaltStack",
    4567: "Sinatra", 4646: "Nomad", 4711: "McAfee-Web",
    4730: "Gearman", 4786: "Cisco-Smart-Install", 4848: "GlassFish",
    4899: "Radmin", 5000: "UPnP/Flask", 5001: "Synology",
    5003: "FileMaker", 5004: "RTP", 5006: "wsm-server",
    5007: "wsm-server-ssl", 5050: "Yahoo-Messenger", 5060: "SIP",
    5061: "SIP-TLS", 5080: "onscreen", 5222: "XMPP",
    5269: "XMPP-Server", 5280: "XMPP-BOSH", 5357: "WSDAPI",
    5432: "PostgreSQL", 5500: "VNC-HTTP", 5555: "Android-ADB",
    5601: "Kibana", 5631: "pcANYWHERE", 5666: "NRPE",
    5672: "AMQP", 5800: "VNC-HTTP", 5900: "VNC",
    5901: "VNC-1", 5902: "VNC-2", 5903: "VNC-3",
    5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    5988: "WBEM-HTTP", 5989: "WBEM-HTTPS", 6000: "X11",
    6001: "X11-1", 6066: "Spark-Worker", 6112: "Diablo",
    6129: "DameWare", 6262: "unknown", 6379: "Redis",
    6443: "Kubernetes-API", 6500: "unknown", 6543: "unknown",
    6588: "AnalogX-Proxy", 6666: "IRC-Alt", 6667: "IRC",
    6881: "BitTorrent", 6969: "TFTP-Alt", 7000: "Cassandra",
    7001: "WebLogic", 7002: "WebLogic-SSL", 7070: "RealServer",
    7071: "Zimbra", 7199: "Cassandra-JMX", 7443: "Oracle-HTTPS",
    7474: "Neo4j", 7547: "CWMP", 7548: "CWMP-SSL",
    7777: "cbt", 7778: "interwise", 8000: "HTTP-Alt",
    8001: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP13",
    8010: "HTTP-Alt", 8020: "HDFS-NameNode", 8042: "YARN-NodeMgr",
    8069: "Odoo", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8082: "HTTP-Alt", 8083: "HTTP-Alt", 8086: "InfluxDB",
    8088: "YARN-RM", 8089: "Splunk", 8090: "HTTP-Alt",
    8091: "Couchbase", 8093: "Couchbase-Query", 8099: "HTTP-Alt",
    8111: "TeamCity", 8123: "Home-Assistant", 8180: "HTTP-Alt",
    8181: "HTTP-Alt", 8200: "Vault", 8222: "HTTP-Alt",
    8243: "HTTPS-Alt", 8280: "HTTP-Alt", 8291: "MikroTik",
    8333: "Bitcoin", 8383: "HTTP-Alt", 8443: "HTTPS-Alt",
    8500: "Consul", 8545: "Ethereum-RPC", 8600: "Consul-DNS",
    8649: "Ganglia", 8834: "Nessus-HTTPS", 8880: "HTTP-Alt",
    8888: "HTTP-Alt", 8899: "HTTP-Alt", 8983: "Apache-Solr",
    9000: "SonarQube", 9001: "Tor", 9042: "Cassandra-CQL",
    9043: "WebSphere-Admin", 9060: "WebSphere",
    9080: "WebSphere-HTTP", 9090: "Prometheus", 9091: "Transmission",
    9100: "JetDirect", 9200: "Elasticsearch", 9201: "Elasticsearch",
    9300: "Elasticsearch-Transport", 9418: "Git", 9443: "HTTPS-Alt",
    9500: "ISPmanager", 9595: "unknown", 9600: "NNMI",
    9090: "Prometheus", 9999: "Abyss", 10000: "Webmin",
    10001: "SCP-Config", 10250: "Kubelet", 10255: "Kubelet-RO",
    10443: "HTTPS-Alt", 11211: "Memcached", 11235: "unknown",
    11311: "ROS-Master", 12345: "NetBus", 13579: "unknown",
    14147: "unknown", 15672: "RabbitMQ-Mgmt", 16010: "HBase-Master",
    16080: "HTTP-Alt", 16992: "AMT-HTTP", 16993: "AMT-HTTPS",
    17000: "unknown", 18080: "HTTP-Alt", 19888: "YARN-History",
    20000: "DNP", 20880: "Dubbo", 25565: "Minecraft",
    25672: "RabbitMQ", 27017: "MongoDB", 27018: "MongoDB-Shard",
    27019: "MongoDB-Config", 28017: "MongoDB-HTTP",
    30000: "NDMPS", 31337: "BackOrifice", 32768: "Filenet",
    33060: "MySQL-X", 33848: "unknown", 35357: "Keystone-Admin",
    44443: "HTTPS-Alt", 47001: "WinRM", 49152: "unknown",
    50000: "IBM-DB2", 50070: "HDFS-Web", 61616: "ActiveMQ",
    62078: "iPhone-Sync",
}

# Ports that should not normally be exposed to the public internet.
_RISKY_PORTS: frozenset[int] = frozenset({
    23, 135, 137, 138, 139, 445, 512, 513, 514,
    1433, 1434, 1521, 2049, 3306, 3389,
    5432, 5900, 5901, 5902, 5903,
    6379, 6667, 9200, 11211, 27017,
    31337, 50000,
})


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
                banner = data.decode("utf-8", errors="replace").replace("\x00", "").strip()
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


def _naabu_to_port_scan_result(host: str, naabu_result, ports_scanned: int = 250) -> PortScanResult:
    """Map a NaabuScanResult to the existing PortScanResult model."""
    open_ports = []
    ip = ""
    for p in naabu_result.ports:
        if p.ip:
            ip = p.ip
        service = _TOP_PORTS.get(p.port, "unknown")
        open_ports.append(OpenPort(
            port=p.port,
            service=service,
            banner="",
            is_risky=p.port in _RISKY_PORTS,
        ))
    open_ports.sort(key=lambda p: p.port)
    return PortScanResult(
        target=host,
        ip=ip,
        open_ports=open_ports,
        ports_scanned=ports_scanned,
    )


async def scan_ports(
    host: str,
    *,
    ports: dict[int, str] | None = None,
    timeout: int = PORT_SCAN_TIMEOUT,
    concurrency: int = PORT_SCAN_CONCURRENCY,
) -> PortScanResult:
    """Scan *host* for open TCP ports.

    Uses naabu via the PD tools sidecar when available, otherwise falls
    back to the built-in Python TCP connect scanner.
    """
    if PD_TOOLS_API_URL and ports is None:
        try:
            from .naabu_client import run_naabu_scan
            naabu_result = await run_naabu_scan(host, timeout=NAABU_TIMEOUT)
            if naabu_result and not naabu_result.error:
                if NAABU_PORT_RANGE.startswith("top-"):
                    scanned = int(NAABU_PORT_RANGE.removeprefix("top-"))
                else:
                    scanned = sum(
                        (int(b) - int(a) + 1) if "-" in part else 1
                        for part in NAABU_PORT_RANGE.split(",")
                        for a, _, b in [part.partition("-")] if a
                    ) if NAABU_PORT_RANGE else 250
                return _naabu_to_port_scan_result(host, naabu_result, ports_scanned=scanned)
            logger.info("Naabu returned error for %s, falling back to Python: %s", host, naabu_result.error)
        except Exception as exc:
            logger.warning("Naabu scan failed for %s, falling back to Python: %s", host, exc)
    return await _scan_ports_python(host, ports=ports, timeout=timeout, concurrency=concurrency)


async def _scan_ports_python(
    host: str,
    *,
    ports: dict[int, str] | None = None,
    timeout: int = PORT_SCAN_TIMEOUT,
    concurrency: int = PORT_SCAN_CONCURRENCY,
) -> PortScanResult:
    """Built-in Python TCP connect scanner."""
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
