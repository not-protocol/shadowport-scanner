"""
core/scan_profiles.py — ShadowPort Scanner v2.1.0

Five scan profiles as frozen dataclasses.
Each maps to a specific nmap flags set, timeout, and privilege requirement.
"""

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class ScanProfile:
    key:             str
    name:            str
    nmap_flags:      str
    timeout_seconds: int
    requires_root:   bool
    description:     str
    eta_seconds:     int


# ─── Profile definitions ──────────────────────────────────────────────────────

FastLabScan = ScanProfile(
    key="fast",
    name="Fast Lab Scan",
    nmap_flags="",
    timeout_seconds=60,
    requires_root=False,
    description="Top 1000 ports — quick check with minimal noise. Best for initial triage.",
    eta_seconds=15,
)

DeepEnumeration = ScanProfile(
    key="deep",
    name="Deep Enumeration",
    nmap_flags="-p- -sV",
    timeout_seconds=600,
    requires_root=False,
    description="All 65535 TCP ports with service version detection. Thorough lab enumeration.",
    eta_seconds=180,
)

WebServerAnalysis = ScanProfile(
    key="web",
    name="Web Server Analysis",
    nmap_flags="-p 80,443,8080,8443,8000,8888,3000,5000 -sV --script http-headers,http-title",
    timeout_seconds=120,
    requires_root=False,
    description="Focused scan on common web ports with HTTP header and title extraction.",
    eta_seconds=30,
)

StealthScan = ScanProfile(
    key="stealth",
    name="Stealth SYN Scan",
    nmap_flags="-sS -T2",
    timeout_seconds=180,
    requires_root=True,
    description="Half-open SYN scan with slow timing. Lower IDS footprint. Requires root.",
    eta_seconds=60,
)

VulnerabilityAudit = ScanProfile(
    key="vuln",
    name="Vulnerability Audit",
    nmap_flags="--script vuln -sV",
    timeout_seconds=300,
    requires_root=False,
    description="NSE vulnerability scripts against detected services. Educational use only.",
    eta_seconds=120,
)


# ─── Registry ─────────────────────────────────────────────────────────────────

ALL_PROFILES: list[ScanProfile] = [
    FastLabScan,
    DeepEnumeration,
    WebServerAnalysis,
    StealthScan,
    VulnerabilityAudit,
]

_PROFILE_MAP: dict[str, ScanProfile] = {p.key: p for p in ALL_PROFILES}


def get_profile(key: str) -> ScanProfile | None:
    return _PROFILE_MAP.get(key)


def get_profile_by_index(idx: int) -> ScanProfile | None:
    """1-based index for menu selection."""
    if 1 <= idx <= len(ALL_PROFILES):
        return ALL_PROFILES[idx - 1]
    return None


def print_profiles_menu() -> None:
    """Print a numbered profile menu to stdout (fallback non-TUI mode)."""
    print("\n  ┌─ Scan Profiles ──────────────────────────────────────────┐")
    for i, p in enumerate(ALL_PROFILES, 1):
        root_tag = " [root]" if p.requires_root else ""
        print(f"  │  [{i}] {p.name:<25} {p.description[:38]}{root_tag}")
    print("  │  [c] Cancel")
    print("  └───────────────────────────────────────────────────────────┘\n")
