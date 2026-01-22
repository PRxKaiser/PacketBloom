#!/usr/bin/env python3
# core.py - PacketBloom main CLI (final, PurpleRose banner replaced)
# Requirements: colorama, scapy, backend (pybind11 module), analyzers.flows, analyzers.rules

import os
import time
import json
from datetime import datetime
from colorama import Fore, Style, init
from scapy.all import rdpcap

# Project analyzers (assumed present)
from analyzers.flows import build_flows, build_flows_from_records
from analyzers.rules import detect_anomalies

init(autoreset=True)

# === BANNER: ===
BANNER = [
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡞⢀⣾⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⠀⣼⣿⣿⣿⡏⠉⠙⠛⠃⠸⠿⣿⣿⣿⠀⠀",
"⠀⠀⠀⠀⠀⠀⠀⣤⣤⡄⠸⣿⣿⣦⡈⢻⣿⣿⡇⣾⣿⣿⣷⣶⠀⢸⣿⣿⡆⠀",
"⠀⠀⠀⠀⠀⠀⠀⠙⠿⣷⠀⣿⣿⣿⣷⣄⠙⣿⣧⣈⣉⣀⣿⣿⠀⢸⣿⣿⡇⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣧⡈⠻⠿⠿⠛⠛⠛⠃⢸⣿⣿⡇⠀",
"⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣧⡈⠛⠿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣿⣿⣿⠿⠛⠁⠀",
"⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⠷⠂⢀⠙⠻⢿⣿⣿⣿⣿⡿⠟⢋⣡⣄⠀⠀⠀",
"⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠀⢰⣾⣿⡀⢰⣤⣈⠙⢋⣡⠀⠘⠻⠿⢿⣷⡀⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡿⠛⠃⠈⠻⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣟⡀⡀⠀⠀⠀⠉⠿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠀⣴⡀⠀⣠⣾⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠙⠀⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠸⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
"⠀⠀⠀⠀⠒⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
]

MENU_BOX = [
"╔══════════════════════════════════════════════╗",
"║ [1] Analyze PCAP                            ║",
"║ [2] Save last result (JSON)                 ║",
"║ [3] Live Capture                            ║",
"║ [4] Exit                                    ║",
"╚══════════════════════════════════════════════╝",
]

# === 
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_menu_with_banner():
    """Show banner and menu side by side (used only for main menu)."""
    banner_colored = [Fore.MAGENTA + Style.BRIGHT + l + Style.RESET_ALL for l in BANNER]
    menu_colored = [Fore.CYAN + Style.BRIGHT + l + Style.RESET_ALL for l in MENU_BOX]
    height = max(len(banner_colored), len(menu_colored))
    banner_colored += [""] * (height - len(banner_colored))
    menu_colored += [""] * (height - len(menu_colored))
    gap = "   "
    banner_width = 70
    for b, m in zip(banner_colored, menu_colored):
        print(f"{b:<{banner_width}}{gap}{m}")

def print_table_only(flows):
    """Print flows table without banner."""
    header = Fore.CYAN + Style.BRIGHT + "SRC_IP         DST_IP         PROTO   PACKETS   BYTES     NOTE" + Style.RESET_ALL
    sep = "---------------------------------------------------------------"
    print("\n" + header)
    print(sep)
    if not flows:
        print(Fore.YELLOW + "(no flows captured)" + Style.RESET_ALL)
        return
    for _, f in flows.items():
        notes = detect_anomalies(f)
        note = "; ".join(notes) if notes else ""
        line = f"{f['src_ip']:<14}{f['dst_ip']:<14}{f['protocol']:<8}{f['count']:<9}{f['bytes']:<10}{note}"
        print(Fore.YELLOW + line + Style.RESET_ALL)

def save_json(flows, outpath):
    out = []
    for _, f in flows.items():
        notes = detect_anomalies(f)
        out.append({
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
            "protocol": f["protocol"],
            "packets": f["count"],
            "bytes": f["bytes"],
            "start": datetime.fromtimestamp(f["start_ts"]).isoformat() if f.get("start_ts") else None,
            "end": datetime.fromtimestamp(f["end_ts"]).isoformat() if f.get("end_ts") else None,
            "notes": notes
        })
    with open(outpath, "w", encoding="utf-8") as fp:
        json.dump(out, fp, indent=2)
    print(Fore.GREEN + f"[√] Saved JSON: {outpath}" + Style.RESET_ALL)

def menu():
    print_menu_with_banner()

# === Main loop ===
def main():
    clear_screen()
    menu()
    last_flows = None

    while True:
        choice = input(Fore.MAGENTA + "→ Select: " + Style.RESET_ALL).strip()
        if choice == "1":
            path = input("PCAP path: ").strip()
            try:
                pkts = rdpcap(path)
            except Exception as e:
                print(Fore.RED + f"[×] Failed to read PCAP: {e}" + Style.RESET_ALL)
                time.sleep(2)
                clear_screen()
                menu()
                continue

            ipf = input("Filter IP (optional): ").strip() or None
            pf = input("Filter port (optional): ").strip()
            portf = int(pf) if pf else None
            protof = input("Filter protocol [TCP/UDP/ICMP] (optional): ").strip().upper() or None

            flows = build_flows(pkts, ip_filter=ipf, port_filter=portf, proto_filter=protof)
            last_flows = flows
            print_table_only(flows)

        elif choice == "2":
            if not last_flows:
                print(Fore.RED + "[×] No analysis yet." + Style.RESET_ALL)
                time.sleep(1.5)
                clear_screen()
                menu()
                continue
            outp = input("Output JSON path: ").strip() or "packetbloom_report.json"
            save_json(last_flows, outp)
            time.sleep(1.2)
            clear_screen()
            menu()

        elif choice == "3":
            try:
                import backend
            except Exception as e:
                print(Fore.RED + f"[×] Backend import failed: {e}" + Style.RESET_ALL)
                time.sleep(2)
                clear_screen()
                menu()
                continue

            iface = input("Interface (e.g., eth0, ens33, wlan0): ").strip() or "eth0"
            maxp = input("Max packets [default 1000]: ").strip()
            max_packets = int(maxp) if maxp else 1000
            timeout_ms = 1000

            save_pcap = input("Save captured packets as PCAP? [y/N]: ").strip().lower() == "y"
            dumpfile = ""
            if save_pcap:
                dumpfile = input("Output PCAP path [default capture.pcap]: ").strip() or "capture.pcap"

            print(Fore.CYAN + f"[…] Capturing on {iface} (max {max_packets}) …" + Style.RESET_ALL)
            try:
                # backend.capture_packets(iface, max_packets, timeout_ms, dumpfile)
                recs = backend.capture_packets(iface, max_packets, timeout_ms, dumpfile)
            except TypeError:
                # Fallback: backend without dumpfile support
                try:
                    recs = backend.capture_packets(iface, max_packets, timeout_ms)
                    if save_pcap:
                        print(Fore.YELLOW + "[!] Backend does not support direct PCAP dump; file not saved." + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[×] Capture error: {e}" + Style.RESET_ALL)
                    time.sleep(2)
                    clear_screen()
                    menu()
                    continue
            except Exception as e:
                print(Fore.RED + f"[×] Capture error: {e}" + Style.RESET_ALL)
                time.sleep(2)
                clear_screen()
                menu()
                continue

            if save_pcap and dumpfile:
                print(Fore.GREEN + f"[√] Saved PCAP: {dumpfile}" + Style.RESET_ALL)

            # Normalize recs to dict-like list
            records = []
            for r in recs:
                src = getattr(r, "src_ip", None) or (r.get("src_ip") if isinstance(r, dict) else "")
                dst = getattr(r, "dst_ip", None) or (r.get("dst_ip") if isinstance(r, dict) else "")
                proto = getattr(r, "proto", None) or (r.get("proto") if isinstance(r, dict) else "OTHER")
                sport = getattr(r, "sport", None) or (r.get("sport") if isinstance(r, dict) else 0)
                dport = getattr(r, "dport", None) or (r.get("dport") if isinstance(r, dict) else 0)
                length = getattr(r, "length", None) or (r.get("length") if isinstance(r, dict) else 0)
                ts = getattr(r, "ts", None) or (r.get("ts") if isinstance(r, dict) else None)
                records.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "proto": proto,
                    "sport": sport,
                    "dport": dport,
                    "length": length,
                    "ts": ts
                })

            ipf = input("Filter IP (optional): ").strip() or None
            pf = input("Filter port (optional): ").strip()
            portf = int(pf) if pf else None
            protof = input("Filter protocol [TCP/UDP/ICMP] (optional): ").strip().upper() or None

            flows = build_flows_from_records(records, ip_filter=ipf, port_filter=portf, proto_filter=protof)
            last_flows = flows
            print_table_only(flows)

        elif choice == "4":
            print(Fore.GREEN + "Exiting PacketBloom." + Style.RESET_ALL)
            break

        else:
            print(Fore.RED + "[×] Invalid choice" + Style.RESET_ALL)
            time.sleep(1.2)
            clear_screen()
            menu()

if __name__ == "__main__":
    main()
