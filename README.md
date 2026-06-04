# ShadowPort Scanner v1.3.0

> "From scanner to reconnaissance platform."

A modular Python-based network port scanner built on Nmap — designed for ethical hackers, cybersecurity students, and home lab enthusiasts.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have written authorization to test.

---

## What's New in v1.3.0

| Feature | v1.2 | v1.3 |
|---|---|---|
| Scan modes | 8 | 8 |
| Privilege check on startup | basic | **interactive with continue prompt** |
| Root mode warning | warning only | **disable-or-warn per mode** |
| Report permission fix | ✗ | ✅ **auto chmod 644** |
| SQLite scan history | ✗ | ✅ |
| Scan comparison (diff) | ✗ | ✅ |
| Service intelligence panel | ✗ | ✅ |
| Risk scoring system | ✗ | ✅ |
| Scan profiles | ✗ | ✅ Fast / Deep / Lab / Stealth |
| Plugin system | ✗ | ✅ DNS Lookup + Banner Grabber |
| Subnet / CIDR scanning | ✗ | ✅ |
| HTML report with risk bar | basic | **enhanced + intel rows** |
| Config module | basic | **config/settings.py** |

---

## Folder Structure

```
shadowport-v1.3/
├── main.py              # Entry point — full workflow
├── scanner.py           # Nmap engine + service intel + risk scoring
├── output.py            # Terminal UI, progress bar, comparison view
├── reports.py           # TXT / JSON / XML / HTML export
├── database.py          # SQLite scan history + comparison
├── profiles.py          # Scan profile presets
├── config/
│   ├── __init__.py
│   └── settings.py      # Version, paths, modes, profiles, service intel DB
├── plugins/
│   ├── __init__.py      # Plugin loader (auto-discovery)
│   ├── base.py          # BasePlugin abstract class
│   ├── dns_lookup.py    # Built-in: DNS forward + reverse lookup
│   └── banner_grabber.py  # Built-in: TCP banner grabbing
├── requirements.txt
├── README.md
├── reports/             # Auto-created — scan reports
├── logs/                # Auto-created — SQLite DB
├── assets/
└── screenshots/
```

---

## Setup

### 1. Install Nmap

```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu / Kali
sudo apt install nmap
```

### 2. Install Python dependencies

```bash
# Install under sudo — prevents the 'no module' error when using sudo python
sudo pip install python-nmap colorama --break-system-packages
```

### 3. Fix folder permissions (if needed)

```bash
sudo chown -R $USER:$USER reports/ logs/
```

---

## Usage

```bash
# Standard (modes 1, 2, 3, 6, 8 + all features)
python main.py

# Full access — unlocks OS Detection, Aggressive, Stealth SYN
sudo python main.py
```

---

## Scan Modes

| # | Mode | Nmap Equivalent | Root? | ETA |
|---|---|---|---|---|
| 1 | Quick Scan | `nmap <target>` | No | ~15s |
| 2 | Full TCP Scan | `nmap -p-` | No | ~2min |
| 3 | Service Detection | `nmap -sV` | No | ~30s |
| 4 | OS Detection | `nmap -O` | **Yes** | ~25s |
| 5 | Aggressive Scan | `nmap -A` | **Yes** | ~60s |
| 6 | Host Discovery | `nmap -sn` | No | ~5s |
| 7 | Stealth SYN Scan | `nmap -sS` | **Yes** | ~20s |
| 8 | Vuln Scripts | `nmap --script vuln` | No | ~90s |

---

## Scan Profiles

Type `p` at the mode prompt to select a one-click profile:

| Profile | Mode | Best For |
|---|---|---|
| Fast | Quick Scan | Quick check, minimal noise |
| Deep | Full TCP | Thorough lab enumeration |
| Lab | Aggressive | VM/HTB/TryHackMe targets |
| Stealth | SYN Scan | Lower-footprint recon (root) |

---

## Service Intelligence

After a scan, type `y` when asked about service intelligence to see:

```
22/tcp   open   ssh
     ├─ Use : Secure remote shell / administration
     └─ Risk: Weak credentials allow unauthorized access. Ensure key-based auth.
```

Educational mode — not vulnerability detection.

---

## Risk Score

Every scan produces an informational risk score:

```
Risk Score: 42/100  [MEDIUM EXPOSURE]
```

Based on which services are open and their typical attack surface. Not a CVE scanner.

---

## Subnet Scanning

Enter a CIDR range as the target:

```
Enter target: 192.168.1.0/24
```

ShadowPort will ping-sweep the subnet, list active hosts, then offer to scan all of them.

---

## Scan Comparison

Type `c` at the mode prompt after running 2+ scans on the same target:

```
Previous scan: 2026-06-01  (open: 2)
Current scan : 2026-06-04  (open: 3)

✚ New ports detected:
    → 3306/tcp

═ Unchanged: 22, 80
```

---

## Plugins

Built-in plugins (type `x` after a scan):

- **dns_lookup** — Forward and reverse DNS resolution
- **banner_grabber** — Grab service banners from open TCP ports

### Writing Your Own Plugin

```python
# plugins/my_plugin.py
from plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    name        = "my_plugin"
    description = "Does something useful"
    version     = "1.0"

    def run(self, target: str, scan_data: dict) -> dict:
        return {"output": f"Hello from {target}!"}
```

Drop it in `plugins/` — it loads automatically next run.

---

## Report Formats

| Format | Description |
|---|---|
| TXT | Plain text with service intel |
| JSON | Machine-readable with risk data |
| XML | Structured with risk attributes |
| HTML | Dark-themed browser report with risk bar ⭐ |

Reports always write to `reports/` inside the project folder and are `chmod 644` automatically.

---

## Roadmap

### v1.3.0 ✅ (Current)
- Improved root privilege handling
- Service intelligence (educational)
- Informational risk scoring
- Scan comparison (diff)
- SQLite scan history
- Scan profiles
- Plugin architecture + 2 built-in plugins
- Subnet / CIDR scanning
- Enhanced HTML reports
- Permission-safe report writing

### v2.0.0 (Planned)
- Rich / Textual terminal dashboard
- Async parallel multi-target scanning
- UDP scanning
- Advanced NSE script presets
- AI-assisted port explanation
- HTML charts (Chart.js)
- Scan scheduling
- Export to PDF

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning may violate local, state, or federal law.
The authors assume no liability for misuse.
