#!/usr/bin/env python3
"""
main.py
-------
Entry point for the Python Security Toolkit.
Presents a menu, dispatches to the selected module, and handles
top-level errors so a bad input never crashes the whole program.

NOTE ON SCOPE:
This build includes fully implemented, defensible modules:
  - MAC Changer
  - Network Scanner (ARP discovery)
  - ARP Spoof Detector (defensive/monitoring only)

The ARP Spoofer, Packet Sniffer, Network Jammer, and DNS Spoofer modules
are intentionally left as documented stubs rather than working attack
code. See README.md ("Scope & Responsible-Use Notes") for why, and for
guidance on discussing this with your instructor if the assignment
requires all seven modules to be functional.
"""

import sys

MENU = """
==========================================
   PYTHON SECURITY TOOLKIT (Lab Edition)
==========================================
 1) MAC Changer
 2) Network Scanner (ARP Discovery)
 3) ARP Spoof Detector
 4) ARP Spoofer          [not implemented — see README]
 5) Packet Sniffer       [not implemented — see README]
 6) Network Jammer       [not implemented — see README]
 7) DNS Spoofer          [not implemented — see README]
 0) Exit
==========================================
"""

NOT_IMPLEMENTED_NOTE = (
    "[-] This module is not implemented in this build.\n"
    "    It performs active network interception/manipulation and was\n"
    "    excluded on purpose. See README.md for details and how to\n"
    "    discuss this scope decision with your instructor.\n"
)


def dispatch(choice: str):
    if choice == "1":
        from modules import mac_changer
        mac_changer.run()
    elif choice == "2":
        from modules import network_scanner
        network_scanner.run()
    elif choice == "3":
        from modules import arp_spoof_detector
        arp_spoof_detector.run()
    elif choice in ("4", "5", "6", "7"):
        print(NOT_IMPLEMENTED_NOTE)
    elif choice == "0":
        print("Goodbye.")
        sys.exit(0)
    else:
        print("[-] Invalid choice. Please select a number from the menu.")


def main():
    while True:
        print(MENU)
        choice = input("Select an option: ").strip()
        try:
            dispatch(choice)
        except KeyboardInterrupt:
            print("\n[-] Interrupted. Returning to menu.")
        except Exception as e:
            # Catch-all so one module's failure doesn't kill the whole toolkit
            print(f"[-] Module error: {e}")

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()