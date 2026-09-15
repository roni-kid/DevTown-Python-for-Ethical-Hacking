"""
network_scanner.py
-------------------
Discovers live hosts on a local network/subnet by broadcasting ARP requests
and recording which IPs respond, along with their MAC addresses.

Concept:
  ARP ("who has this IP?") is how devices on the same LAN find each other's
  MAC addresses. Broadcasting a request for every address in a subnet and
  collecting the replies is a lightweight, reliable way to enumerate active
  hosts — much faster than pinging every address individually.

Improvements over the classroom version:
  - Target/range comes from CLI input or argparse, never hard-coded.
  - Validates the IP/CIDR format before sending anything on the wire.
  - Returns structured results (list of dicts) instead of only printing,
    so other modules/tests can reuse this function.
  - Table-formatted output instead of raw scapy .show() dumps.
"""

import argparse

from utils.network_utils import require_scapy, is_valid_ip_or_range, confirm_authorized_use

import scapy.all as scapy  # safe: require_scapy() is checked before use in run()


def scan(ip_range: str, timeout: float = 2.0):
    """
    Send a broadcast ARP request for `ip_range` (single IP or CIDR, e.g.
    '192.168.1.1/24') and return a list of {'ip': ..., 'mac': ...} dicts
    for every host that responded.
    """
    require_scapy()
    if not is_valid_ip_or_range(ip_range):
        raise ValueError(f"Invalid IP or IP range: {ip_range}")

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _unanswered = scapy.srp(packet, timeout=timeout, verbose=False)

    results = []
    for _sent, received in answered:
        results.append({"ip": received.psrc, "mac": received.hwsrc})
    return results


def print_results(results):
    if not results:
        print("[-] No hosts responded. Check the range, your permissions, or interface.")
        return

    print(f"\n{'IP Address':<18}{'MAC Address'}")
    print("-" * 40)
    for host in results:
        print(f"{host['ip']:<18}{host['mac']}")
    print(f"\n[+] {len(results)} host(s) found.")


def run():
    """Entry point called from the main CLI menu."""
    print("\n=== Network Scanner (ARP Discovery) ===")

    if not confirm_authorized_use("Network Scanner"):
        print("[-] Aborted — authorization not confirmed.")
        return

    ip_range = input("Target IP or range (e.g. 192.168.1.1/24): ").strip()

    try:
        results = scan(ip_range)
        print_results(results)
    except ValueError as e:
        print(f"[-] {e}")
    except PermissionError:
        print("[-] Permission denied. ARP scanning usually requires root (try sudo).")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


def _cli():
    """Optional standalone CLI: python3 network_scanner.py -t 192.168.1.0/24"""
    parser = argparse.ArgumentParser(description="ARP-based LAN scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or IP range (CIDR)")
    args = parser.parse_args()
    print_results(scan(args.target))


if __name__ == "__main__":
    _cli()