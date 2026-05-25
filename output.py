"""
output.py — ShadowPort Scanner
Handles colored terminal output, formatting, and tables.
"""

from colorama import Fore, Back, Style, init

# Initialize colorama (auto-reset after each print)
init(autoreset=True)


BANNER = r"""
{}{}
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝██║   ██║██████╔╝   ██║   
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║     ╚██████╔╝██║  ██║   ██║   
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
{}{}
                         ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗     
                         ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗    
                         ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝    
                         ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗    
                         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║    
                         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    
{}
              [ Network Reconnaissance & Port Analysis Tool ]  v1.0
              [ Use ONLY on systems you own or are authorized to test ]
{}
""".format(
    Fore.RED + Style.BRIGHT,
    "",
    Fore.CYAN,
    "",
    Fore.YELLOW,
    Style.RESET_ALL,
)


def print_banner():
    """Print the ShadowPort Scanner ASCII banner."""
    print(BANNER)


def print_menu():
    """Print the main scan mode selection menu."""
    print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "  ║         SELECT SCAN MODE             ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╠══════════════════════════════════════╣")
    options = [
        ("1", "Quick Scan         ", "Top common ports"),
        ("2", "Full TCP Scan      ", "All 65535 ports"),
        ("3", "Service Detection  ", "Versions & services"),
        ("4", "OS Detection       ", "Operating system"),
        ("5", "Aggressive Scan    ", "Full -A analysis"),
        ("6", "Exit               ", "Quit ShadowPort"),
    ]
    for num, label, desc in options:
        color = Fore.RED if num == "6" else Fore.GREEN
        print(
            Fore.CYAN + "  ║  "
            + color + Style.BRIGHT + f"[{num}]"
            + Fore.WHITE + f"  {label}"
            + Fore.YELLOW + f"— {desc}"
            + Fore.CYAN + "  ║"
        )
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════╝\n")


def print_info(msg: str):
    """Print an informational message."""
    print(Fore.CYAN + Style.BRIGHT + "[*] " + Style.RESET_ALL + msg)


def print_success(msg: str):
    """Print a success message."""
    print(Fore.GREEN + Style.BRIGHT + "[+] " + Style.RESET_ALL + msg)


def print_error(msg: str):
    """Print an error message."""
    print(Fore.RED + Style.BRIGHT + "[!] ERROR: " + Style.RESET_ALL + msg)


def print_warning(msg: str):
    """Print a warning message."""
    print(Fore.YELLOW + Style.BRIGHT + "[~] " + Style.RESET_ALL + msg)


def print_section(title: str):
    """Print a section header."""
    width = 50
    print()
    print(Fore.MAGENTA + Style.BRIGHT + "  ┌" + "─" * width + "┐")
    padding = (width - len(title) - 2) // 2
    print(Fore.MAGENTA + Style.BRIGHT + "  │" + " " * padding + f" {title} " + " " * padding + "│")
    print(Fore.MAGENTA + Style.BRIGHT + "  └" + "─" * width + "┘")
    print()


def print_results_table(scan_data: dict):
    """
    Print a formatted table of scan results.

    Args:
        scan_data: dict with keys 'host', 'state', 'ports'
                   ports is a list of dicts: {port, proto, state, service, version}
    """
    host = scan_data.get("host", "Unknown")
    host_state = scan_data.get("state", "Unknown")
    ports = scan_data.get("ports", [])
    hostname = scan_data.get("hostname", "")
    os_matches = scan_data.get("os_matches", [])

    print_section("SCAN RESULTS")

    # Host info block
    print(Fore.CYAN + "  Target   : " + Fore.WHITE + Style.BRIGHT + host)
    if hostname:
        print(Fore.CYAN + "  Hostname : " + Fore.WHITE + hostname)
    state_color = Fore.GREEN if host_state == "up" else Fore.RED
    print(Fore.CYAN + "  Status   : " + state_color + Style.BRIGHT + host_state.upper())

    # OS detection
    if os_matches:
        print(Fore.CYAN + "  OS       : " + Fore.YELLOW + os_matches[0])

    print()

    if not ports:
        print_warning("No open ports found.")
        return

    # Table header
    col_port    = 12
    col_state   = 10
    col_service = 18
    col_version = 30

    header = (
        Fore.WHITE + Style.BRIGHT
        + "  " + "PORT".ljust(col_port)
        + "STATE".ljust(col_state)
        + "SERVICE".ljust(col_service)
        + "VERSION"
    )
    divider = Fore.CYAN + "  " + "─" * (col_port + col_state + col_service + col_version)

    print(header)
    print(divider)

    for p in ports:
        port_str  = f"{p['port']}/{p['proto']}".ljust(col_port)
        state_str = p["state"].ljust(col_state)
        svc_str   = p["service"].ljust(col_service)
        ver_str   = p.get("version", "")[:col_version]

        state_color = Fore.GREEN if p["state"] == "open" else Fore.YELLOW

        print(
            "  "
            + Fore.WHITE + Style.BRIGHT + port_str
            + state_color + state_str
            + Fore.CYAN + svc_str
            + Fore.YELLOW + ver_str
        )

    print(divider)
    open_count = sum(1 for p in ports if p["state"] == "open")
    print()
    print_success(f"Scan complete — {open_count} open port(s) found on {host}")
    print()
