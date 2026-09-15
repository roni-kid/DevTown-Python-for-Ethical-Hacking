"""
arp_spoof_detector.py
----------------------
Passively monitors ARP traffic and flags inconsistencies that indicate
ARP cache poisoning (i.e., someone else running an ARP spoofing attack
on the network you're monitoring).

Concept:
  A legitimate ARP reply's source MAC should match the MAC actually
  reachable at that source IP. An attacker forging replies will claim
  a different IP->MAC mapping than what's really on the wire. By
  actively re-querying the claimed IP and comparing MACs, mismatches
  reveal spoofing attempts.

This is a purely defensive/monitoring tool: it listens and alerts,
it does not send forged packets or alter anything on the network.

Improvements over the classroom version:
  - Interface comes from CLI input, not hard-coded ("Wi-Fi").
  - Validates interface existence before sniffing.
  - Logs alerts with timestamps instead of a single generic print.
  - Graceful Ctrl+C shutdown and clear permission-error handling.
"""

import datetime

from utils.network_utils import require_scapy, get_mac, interface_exists

import scapy.all as scapy  # safe: require_scapy() checked in run()


def _log(message: str):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")


def _make_callback(alert_log):
    def process_packet(packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # is-at (reply)
            src_ip = packet[scapy.ARP].psrc
            claimed_mac = packet[scapy.ARP].hwsrc
            real_mac = get_mac(src_ip, timeout=1.0)

            if real_mac and real_mac.lower() != claimed_mac.lower():
                msg = (
                    f"POSSIBLE ARP SPOOFING: {src_ip} claimed by {claimed_mac}, "
                    f"but actually resolves to {real_mac}"
                )
                _log(f"[!] {msg}")
                alert_log.append(msg)
            else:
                _log(f"[+] ARP reply OK: {src_ip} -> {claimed_mac}")

    return process_packet


def monitor(interface: str, packet_count: int = 0):
    """
    Sniff ARP traffic on `interface` and report suspicious replies.
    packet_count=0 means sniff indefinitely until interrupted.
    Returns the list of alert messages collected during the run.
    """
    require_scapy()
    if not interface_exists(interface):
        raise ValueError(f"Interface '{interface}' was not found on this machine.")

    alert_log = []
    _log(f"Monitoring ARP traffic on '{interface}'. Press Ctrl+C to stop.")
    try:
        scapy.sniff(
            iface=interface,
            store=False,
            prn=_make_callback(alert_log),
            count=packet_count,
        )
    except KeyboardInterrupt:
        _log("Stopped by user.")
    return alert_log


def run():
    """Entry point called from the main CLI menu."""
    print("\n=== ARP Spoof Detector ===")
    interface = input("Interface to monitor (e.g. eth0, wlan0): ").strip()

    try:
        alerts = monitor(interface)
        print(f"\n[+] Session ended. {len(alerts)} alert(s) recorded.")
    except ValueError as e:
        print(f"[-] {e}")
    except PermissionError:
        print("[-] Permission denied. Packet sniffing requires root (try sudo).")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


if __name__ == "__main__":
    run()