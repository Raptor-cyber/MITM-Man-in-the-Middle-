# File: core/network_scanner.py

from scapy.all import ARP, Ether, srp
from colorama import Fore, init
from datetime import datetime

init(autoreset=True)

def scan_network(target_ip):
    print(Fore.CYAN + f"[+] Scanning Network: {target_ip}")

    # ARP request packet to broadcast MAC
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        print(Fore.GREEN + f"Found -> IP: {received.psrc} | MAC: {received.hwsrc}")

    if devices:
        filename = f"megadriod_network_scan_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(filename, "w") as f:
            for d in devices:
                f.write(f"IP: {d['ip']} - MAC: {d['mac']}\n")
        print(Fore.YELLOW + f"\n[+] Scan Results Saved to {filename}")
    else:
        print(Fore.RED + "[-] No active devices found on this network.")

    return devices
