# File: core/packet_sniffer.py

from scapy.all import sniff, TCP, IP, Raw, DNSQR, DNS
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

LOG_FILE = "megadriod_sniffer_log.txt"

sensitive_ports = {
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP"
}

def log_packet(pkt_data):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {pkt_data}\n")

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            proto = sensitive_ports.get(sport) or sensitive_ports.get(dport)
            if proto:
                summary = f"{proto} Packet {src}:{sport} -> {dst}:{dport}"
                print(Fore.CYAN + summary)
                log_packet(summary)

            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if any(k in payload.lower() for k in ["user", "pass", "username", "login"]):
                    cred_log = f"[!] Credentials Detected from {src}:\n{payload}\n"
                    print(Fore.YELLOW + cred_log)
                    log_packet(cred_log)

        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode()
            dns_log = f"[DNS] {src} -> {dst} requested {dns_query}"
            print(Fore.MAGENTA + dns_log)
            log_packet(dns_log)

import socket

def get_default_iface():
    """Attempt to detect the default network interface."""
    import psutil
    gateways = psutil.net_if_addrs()
    default_gateways = psutil.net_if_stats()
    # Try to find the first active, non-loopback interface
    for iface, addrs in gateways.items():
        if iface != "lo" and default_gateways[iface].isup:
            return iface
    return None

def start_sniffer(iface=None):
    """Start packet sniffer with automatic interface detection."""
    if not iface:
        iface = get_default_iface()
        if not iface:
            print(Fore.RED + "[!] Could not determine default interface")
            return
    
    print(Fore.GREEN + f"[+] Starting packet sniffer on interface: {iface}")
    sniff(filter="ip", prn=process_packet, iface=iface, store=False)
