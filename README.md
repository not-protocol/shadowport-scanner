# ShadowPort Scanner

A Python-based command-line tool that automates network port scanning using Nmap.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have written authorization to test.

---
## Video Demo

[Watch ShadowPort Demo](https://streamable.com/t75fwr)

---

## Features

- 5 scan modes: Quick, Full TCP, Service Detection, OS Detection, Aggressive
- Colored terminal output with structured port tables
- Save reports in **TXT**, **JSON**, or **XML**
- Input validation and helpful error messages
- Modular architecture — easy to extend

---

## Requirements

- Python 3.10+
- Nmap installed on your system

### Install Nmap

```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu / Kali
sudo apt install nmap
```

### Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

For OS Detection or SYN scans (mode 4/5), run with elevated privileges:

```bash
sudo python main.py
```

---

## Project Structure

```
shadowport-scanner/
├── main.py          # Entry point — menu & workflow
├── scanner.py       # Nmap execution & result parsing
├── output.py        # Colored terminal output & tables
├── report.py        # Save results (TXT, JSON, XML)
├── requirements.txt
├── README.md
└── reports/         # Auto-created; scan reports saved here
```

---

## Scan Modes

| # | Mode               | Nmap Equivalent | Notes                       |
|---|--------------------|-----------------|-----------------------------|
| 1 | Quick Scan         | `nmap <target>` | Top 1000 ports              |
| 2 | Full TCP Scan      | `nmap -p-`      | All 65535 ports (slow)      |
| 3 | Service Detection  | `nmap -sV`      | Versions & banners          |
| 4 | OS Detection       | `nmap -O`       | Requires root               |
| 5 | Aggressive Scan    | `nmap -A`       | OS + services + scripts     |

---

## Example Output

```
  Target   : 192.168.56.101
  Status   : UP

  PORT         STATE     SERVICE           VERSION
  ─────────────────────────────────────────────────────────
  22/tcp       open      ssh               OpenSSH 8.9
  80/tcp       open      http              Apache 2.4.52
  3306/tcp     open      mysql             MySQL 8.0.28
  ─────────────────────────────────────────────────────────

[+] Scan complete — 3 open port(s) found on 192.168.56.101
```

---

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only.
Unauthorized port scanning may violate local, state, or federal laws.
The authors assume no liability for misuse of this software.
