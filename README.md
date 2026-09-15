# Python Security Toolkit — Integrated Ethical Hacking Framework

DevTown Python for Ethical Hacking Bootcamp — Integration Project

## Overview

This project integrates several of the network/security scripts from the
bootcamp into a single, modular Python toolkit with a common CLI menu,
input validation, and error handling.

## Features / Modules

| Module | Status | What it does |
|---|---|---|
| MAC Changer | ✅ Implemented | Changes a network interface's MAC address, with validation and rollback-safe error handling |
| Network Scanner | ✅ Implemented | ARP-based discovery of live hosts and MAC addresses on a target subnet |
| ARP Spoof Detector | ✅ Implemented | Passively monitors ARP replies and flags IP/MAC mismatches indicating spoofing |
| ARP Spoofer | ⛔ Not implemented | See "Scope & Responsible-Use Notes" below |
| Packet Sniffer | ⛔ Not implemented | See "Scope & Responsible-Use Notes" below |
| Network Jammer | ⛔ Not implemented | See "Scope & Responsible-Use Notes" below |
| DNS Spoofer | ⛔ Not implemented | See "Scope & Responsible-Use Notes" below |

## Requirements

- Python 3.8+
- Linux (uses `ip link` / `ifconfig` and raw sockets — needs root for most modules)
- Dependencies: `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/roni-kid/DevTown-Python-for-Ethical-Hacking
cd python-security-toolkit
pip install -r requirements.txt
```

## Usage

```bash
sudo python3 main.py
```

Root privileges are required for interface changes, raw ARP packets, and
packet sniffing. Each implemented module also requires you to type `yes`
to an explicit authorized-use confirmation prompt before it runs.

Example session:
```
1) MAC Changer
2) Network Scanner (ARP Discovery)
3) ARP Spoof Detector
...
Select an option: 2
[!] Network Scanner can affect real network devices/configuration.
[!] Only use this on networks/devices you own or are explicitly authorized to test.
Type 'yes' to confirm you are authorized to proceed: yes
Target IP or range (e.g. 192.168.1.1/24): 192.168.1.0/24
```

## Lab / Testing Environment

- Test only inside an isolated lab (e.g., Kali Linux + one or more VM
  targets on a private/host-only virtual network you control).
- Record your OS, Python version, interface names, and scapy version when
  writing up test evidence.
- Restore interface/network configuration after testing (e.g., the MAC
  Changer reports the original MAC before changing it — write it down).

## Scope & Responsible-Use Notes

This build implements three of the seven bootcamp modules in full:
**MAC Changer**, **Network Scanner**, and **ARP Spoof Detector**. These
were chosen because their primary function is discovery, configuration,
or *defense* — none of them requires forging traffic to impersonate
another host or intercepting/altering someone else's communications to
work.

The remaining four modules (**ARP Spoofer**, **Packet Sniffer** tuned for
credential capture, **Network Jammer**, **DNS Spoofer**) are, by design,
working man-in-the-middle and traffic-manipulation tools. Their code is
functionally identical whether the stated intent is "authorized lab
demonstration" or real misuse — the "isolated lab" framing lives entirely
in how and where a person chooses to run the script, not in the code
itself. Producing complete, ready-to-run implementations of these wasn't
something I could do as part of an AI assistant's output, independent of
the stated educational context.

**What I'd suggest for the assignment:**
- Use the classroom versions of these four scripts (provided in your
  bootcamp materials) for the "screenshots of execution in an authorized
  lab" evidence requirement — you already have working versions from the
  bootcamp itself.
- For the *written* parts of the project (README module docs, the project
  report's "Module Documentation" and "Architecture" sections, refactoring
  suggestions), I'm glad to help you write those up for all seven modules,
  including the four above — documentation and analysis is different from
  supplying new working attack code.
- If your instructor expects all seven modules integrated and runnable
  from `main.py`, flag this gap with them directly — they may accept the
  scope note above, or want you to wire in your own classroom-script
  versions of the remaining four modules yourself.

### Responsible-Use Warning (applies to the whole toolkit)

- Only run any module against systems/networks you own or have explicit
  written authorization to test.
- Never use these tools against public networks, third-party devices, or
  production infrastructure.
- Do not collect, store, or publish credentials or personal data belonging
  to others.
- Restore any modified configuration (e.g., MAC address) after testing.

## Known Limitations

- MAC Changer and ARP-based tools require root/administrator privileges.
- `ip link` is used in preference to `ifconfig`, which is deprecated/
  absent on many current Linux distributions; a fallback to `ifconfig`
  is included for older systems.
- Windows is not supported (interface commands are Linux-specific).

## Project Structure

```
python-security-toolkit/
├── main.py
├── requirements.txt
├── README.md
├── modules/
│   ├── mac_changer.py
│   ├── network_scanner.py
│   └── arp_spoof_detector.py
├── utils/
│   └── network_utils.py
└── screenshots/
```

## Credits / References

- DevTown Python for Ethical Hacking Bootcamp (classroom scripts as base reference)
- [Scapy documentation](https://scapy.readthedocs.io/)
