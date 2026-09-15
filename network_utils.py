"""
network_utils.py
-----------------
Shared helper functions used across multiple toolkit modules.
Centralizing these avoids duplicating MAC-lookup / validation logic
in every module (per assignment requirement: "avoid unnecessary duplication").
"""

import re
import subprocess
import sys

try:
    import scapy.all as scapy
except ImportError:
    scapy = None  # Allows the CLI to still load and show a clear error later


MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
IPV4_RANGE_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}/\d{1,2}$"
)


def require_scapy():
    """Fail fast with a clear message if scapy isn't installed."""
    if scapy is None:
        print("[-] scapy is not installed. Run: pip install scapy")
        sys.exit(1)


def is_valid_mac(mac: str) -> bool:
    return bool(MAC_REGEX.match(mac.strip()))


def is_valid_ip(ip: str) -> bool:
    return bool(IPV4_REGEX.match(ip.strip()))


def is_valid_ip_or_range(value: str) -> bool:
    value = value.strip()
    return bool(IPV4_REGEX.match(value) or IPV4_RANGE_REGEX.match(value))


def interface_exists(interface: str) -> bool:
    """
    Check whether a network interface exists on this machine.
    Uses `ip link show <iface>` (works on modern Linux; ifconfig is deprecated
    on many distros including recent Kali).
    """
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # Fall back to ifconfig if `ip` isn't available
        try:
            result = subprocess.run(
                ["ifconfig", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False


def list_interfaces():
    """Return a list of available network interface names."""
    require_scapy()
    try:
        return scapy.get_if_list()
    except Exception:
        return []


def get_mac(ip: str, timeout: float = 2.0):
    """
    Resolve the MAC address for a given IP using an ARP request.
    Returns None (instead of raising) on failure/timeout so callers
    can handle it gracefully rather than crashing.
    """
    require_scapy()
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    try:
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / request
        answered = scapy.srp(packet, timeout=timeout, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
        return None
    except PermissionError:
        print("[-] Permission denied. ARP resolution requires root privileges (try sudo).")
        return None
    except Exception as e:
        print(f"[-] Failed to resolve MAC for {ip}: {e}")
        return None


def confirm_authorized_use(module_name: str) -> bool:
    """
    Require explicit user confirmation that this module is being run
    against a system/network they own or are authorized to test.
    Required by the project's responsible-use guidelines.
    """
    print(f"\n[!] {module_name} can affect real network devices/configuration.")
    print("[!] Only use this on networks/devices you own or are explicitly authorized to test.")
    answer = input("Type 'yes' to confirm you are authorized to proceed: ").strip().lower()
    return answer == "yes"