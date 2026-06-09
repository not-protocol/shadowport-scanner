"""
core/service_kb.py — ShadowPort Scanner v2.1.0

Service Knowledge Base: maps well-known ports to structured
educational information. Not a vulnerability scanner.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ServiceInfo:
    name:           str
    purpose:        str
    default_port:   int
    common_uses:    tuple
    security_notes: str
    risk_level:     str  # low | medium | high | critical


_KB: dict[int, ServiceInfo] = {
    21: ServiceInfo(
        name="FTP",
        purpose="File Transfer Protocol — unencrypted file transfer",
        default_port=21,
        common_uses=("Legacy file sharing", "Embedded device firmware upload"),
        security_notes="Credentials and data transmitted in plaintext. Replace with SFTP or FTPS.",
        risk_level="high",
    ),
    22: ServiceInfo(
        name="SSH",
        purpose="Secure Shell — encrypted remote administration",
        default_port=22,
        common_uses=("Remote server management", "Encrypted tunneling", "SFTP"),
        security_notes="Disable password auth. Use key-based authentication. Restrict to known IPs.",
        risk_level="medium",
    ),
    23: ServiceInfo(
        name="Telnet",
        purpose="Legacy plaintext remote shell",
        default_port=23,
        common_uses=("Legacy network device management",),
        security_notes="All traffic is unencrypted including credentials. Replace with SSH immediately.",
        risk_level="critical",
    ),
    25: ServiceInfo(
        name="SMTP",
        purpose="Simple Mail Transfer Protocol — email delivery",
        default_port=25,
        common_uses=("Email server", "Mail relay"),
        security_notes="Open relay allows spam abuse. Enforce STARTTLS and authentication.",
        risk_level="medium",
    ),
    53: ServiceInfo(
        name="DNS",
        purpose="Domain Name System — hostname resolution",
        default_port=53,
        common_uses=("Name resolution", "Zone transfers"),
        security_notes="Open resolvers can be abused for amplification DDoS attacks.",
        risk_level="medium",
    ),
    80: ServiceInfo(
        name="HTTP",
        purpose="Hypertext Transfer Protocol — unencrypted web traffic",
        default_port=80,
        common_uses=("Web server", "API endpoints", "Redirect to HTTPS"),
        security_notes="Unencrypted. Sensitive data exposed in transit. Always redirect to HTTPS.",
        risk_level="medium",
    ),
    110: ServiceInfo(
        name="POP3",
        purpose="Post Office Protocol — email retrieval",
        default_port=110,
        common_uses=("Email client access",),
        security_notes="Plaintext credentials without TLS. Use POP3S (port 995) instead.",
        risk_level="medium",
    ),
    143: ServiceInfo(
        name="IMAP",
        purpose="Internet Message Access Protocol — email access",
        default_port=143,
        common_uses=("Email client synchronisation",),
        security_notes="Ensure STARTTLS. Exposed IMAP allows mailbox enumeration.",
        risk_level="medium",
    ),
    443: ServiceInfo(
        name="HTTPS",
        purpose="HTTP over TLS — encrypted web traffic",
        default_port=443,
        common_uses=("Secure web server", "REST APIs", "Web applications"),
        security_notes="Verify TLS version (1.2+ required). Check certificate validity and cipher suites.",
        risk_level="low",
    ),
    445: ServiceInfo(
        name="SMB",
        purpose="Server Message Block — Windows file and printer sharing",
        default_port=445,
        common_uses=("Windows network shares", "Active Directory"),
        security_notes="Target of EternalBlue (MS17-010) and similar exploits. Patch immediately. Block from internet.",
        risk_level="critical",
    ),
    3306: ServiceInfo(
        name="MySQL",
        purpose="MySQL relational database server",
        default_port=3306,
        common_uses=("Web application databases", "Data storage"),
        security_notes="Database should never be internet-exposed. Bind to localhost or restrict by IP.",
        risk_level="high",
    ),
    3389: ServiceInfo(
        name="RDP",
        purpose="Remote Desktop Protocol — Windows graphical remote access",
        default_port=3389,
        common_uses=("Windows remote administration",),
        security_notes="High-value target. Enable NLA. Patch for BlueKeep (CVE-2019-0708). Never expose to internet.",
        risk_level="critical",
    ),
    5432: ServiceInfo(
        name="PostgreSQL",
        purpose="PostgreSQL relational database server",
        default_port=5432,
        common_uses=("Web application databases", "Analytics"),
        security_notes="Restrict to localhost. Use strong passwords. Enable SSL connections.",
        risk_level="high",
    ),
    6379: ServiceInfo(
        name="Redis",
        purpose="In-memory data structure store / cache",
        default_port=6379,
        common_uses=("Caching", "Session storage", "Message broker"),
        security_notes="No authentication by default. Internet-exposed Redis instances frequently compromised for RCE.",
        risk_level="critical",
    ),
    8080: ServiceInfo(
        name="HTTP-Alt",
        purpose="Alternative HTTP port — commonly used by dev servers and proxies",
        default_port=8080,
        common_uses=("Development web servers", "HTTP proxies", "Jenkins", "Tomcat"),
        security_notes="Often runs admin panels or dev tools. Check for default credentials.",
        risk_level="medium",
    ),
    8443: ServiceInfo(
        name="HTTPS-Alt",
        purpose="Alternative HTTPS port",
        default_port=8443,
        common_uses=("Admin panels", "Alternate web apps"),
        security_notes="Verify TLS config same as port 443. Check for exposed admin interfaces.",
        risk_level="medium",
    ),
    27017: ServiceInfo(
        name="MongoDB",
        purpose="MongoDB NoSQL document database",
        default_port=27017,
        common_uses=("Document storage", "Web application databases"),
        security_notes="Historically deployed without authentication. Verify auth is enabled. Never expose to internet.",
        risk_level="critical",
    ),
}

_UNKNOWN = ServiceInfo(
    name="Unknown",
    purpose="Service not identified in knowledge base",
    default_port=0,
    common_uses=("Unknown",),
    security_notes="Investigate manually to determine purpose and exposure risk.",
    risk_level="medium",
)


def get_service_info(port: int) -> ServiceInfo:
    """Return ServiceInfo for a port number, or the unknown fallback."""
    return _KB.get(int(port), _UNKNOWN)


def get_all_known_ports() -> list[int]:
    return sorted(_KB.keys())


def format_service_info(port: int) -> str:
    """Return a formatted multi-line string for terminal display."""
    info = get_service_info(port)
    uses = ", ".join(info.common_uses)
    return (
        f"  Service     : {info.name}\n"
        f"  Purpose     : {info.purpose}\n"
        f"  Common uses : {uses}\n"
        f"  Risk level  : {info.risk_level.upper()}\n"
        f"  Notes       : {info.security_notes}"
    )
