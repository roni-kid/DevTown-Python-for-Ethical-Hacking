"""
mac_changer.py
--------------
Changes the MAC (hardware) address of a specified network interface.

Concept:
  Every NIC ships with a manufacturer-assigned MAC address. The OS lets you
  override the address the kernel reports for that interface. Changing it
  can be used (in an authorized lab) to demonstrate bypassing MAC-based
  filtering on a router/switch you control, or for basic privacy on a
  network you own.

Improvements over the classroom version:
  - No hard-coded interface/MAC — both come from CLI input.
  - Validates interface existence and MAC format before touching anything.
  - Uses `ip link` (modern) with an `ifconfig` fallback, since `ifconfig`
    is deprecated/absent on many current Linux distros.
  - Verifies the change actually applied and reports success/failure.
  - Wrapped in explicit try/except so a failed step doesn't leave the
    interface half-down.
"""

import re
import subprocess

from utils.network_utils import is_valid_mac, interface_exists, confirm_authorized_use


def _run(cmd):
    """Run a command, returning (success, output)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, (result.stdout + result.stderr)
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"


def get_current_mac(interface: str):
    """Read the interface's current MAC address."""
    success, output = _run(["ip", "link", "show", interface])
    if not success:
        success, output = _run(["ifconfig", interface])
        if not success:
            return None
    match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", output)
    return match.group(1) if match else None


def change_mac(interface: str, new_mac: str) -> bool:
    """
    Change the MAC address of `interface` to `new_mac`.
    Returns True on verified success, False otherwise.
    """
    if not interface_exists(interface):
        print(f"[-] Interface '{interface}' was not found on this machine.")
        return False

    if not is_valid_mac(new_mac):
        print(f"[-] '{new_mac}' is not a valid MAC address (expected format aa:bb:cc:dd:ee:ff).")
        return False

    print(f"[*] Current MAC for {interface}: {get_current_mac(interface)}")

    # Prefer `ip link`, since it's the modern replacement for ifconfig
    steps_ip = [
        ["ip", "link", "set", "dev", interface, "down"],
        ["ip", "link", "set", "dev", interface, "address", new_mac],
        ["ip", "link", "set", "dev", interface, "up"],
    ]
    steps_ifconfig = [
        ["ifconfig", interface, "down"],
        ["ifconfig", interface, "hw", "ether", new_mac],
        ["ifconfig", interface, "up"],
    ]

    for step_set, tool_name in ((steps_ip, "ip"), (steps_ifconfig, "ifconfig")):
        all_ok = True
        for cmd in step_set:
            ok, output = _run(cmd)
            if not ok:
                all_ok = False
                break
        if all_ok:
            break
    else:
        print("[-] Failed to change MAC address with both 'ip' and 'ifconfig'.")
        print("[-] This usually means you need root privileges (try running with sudo).")
        return False

    current = get_current_mac(interface)
    if current and current.lower() == new_mac.lower():
        print(f"[+] MAC address successfully changed to {current}")
        return True

    print("[-] MAC change command ran, but verification failed.")
    print(f"[-] Interface now reports: {current}")
    return False


def run():
    """Entry point called from the main CLI menu."""
    print("\n=== MAC Address Changer ===")

    if not confirm_authorized_use("MAC Changer"):
        print("[-] Aborted — authorization not confirmed.")
        return

    interface = input("Interface (e.g. eth0, wlan0): ").strip()
    new_mac = input("New MAC address (aa:bb:cc:dd:ee:ff): ").strip()

    try:
        change_mac(interface, new_mac)
    except PermissionError:
        print("[-] Permission denied. Try running the toolkit with sudo.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


if __name__ == "__main__":
    run()