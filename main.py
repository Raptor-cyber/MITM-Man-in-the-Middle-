# File: main.py
from core.arp_spoofer import start_spoof
from core.packet_sniffer import start_sniffer
from core.network_scanner import scan_network
import re
from colorama import Fore, Style, init
import sys
import os

init(autoreset=True)

def validate_ip(ip):
    """Validate IP address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def get_valid_ip(prompt):
    """Get and validate IP address from user input."""
    while True:
        ip = input(Fore.YELLOW + prompt).strip()
        if validate_ip(ip):
            return ip
        print(Fore.RED + "[!] Invalid IP address format. Use format: xxx.xxx.xxx.xxx")

def validate_interface(iface):
    """Validate network interface name."""
    if os.name == "posix":  # Linux
        return os.path.exists(f"/sys/class/net/{iface}")
    else:  # Windows
        return iface.startswith(("eth", "wlan", "Local Area Connection"))

def get_valid_interface(prompt):
    """Get and validate network interface from user input."""
    while True:
        iface = input(Fore.YELLOW + prompt).strip()
        if validate_interface(iface):
            return iface
        print(Fore.RED + "[!] Invalid interface name")

def validate_subnet(subnet):
    """Validate subnet format (e.g., 192.168.1.0/24)."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, subnet):
        return False
    
    # Validate IP portion
    ip = subnet.split('/')[0]
    if not validate_ip(ip):
        return False
    
    # Validate subnet mask
    mask = int(subnet.split('/')[1])
    return 0 <= mask <= 32

def get_valid_subnet(prompt):
    """Get and validate subnet from user input."""
    while True:
        subnet = input(Fore.YELLOW + prompt).strip()
        if validate_subnet(subnet):
            return subnet
        print(Fore.RED + "[!] Invalid subnet format. Use format: xxx.xxx.xxx.xxx/xx")

def print_banner():
    """Display the program banner."""
    print(Fore.CYAN + "=" * 40)
    print(Fore.CYAN + "=== Megadroid MITM Toolkit ===")
    print(Fore.CYAN + "=" * 40)
    print(Fore.GREEN + "1. ARP Spoof")
    print(Fore.GREEN + "2. Packet Sniffer")
    print(Fore.GREEN + "3. Network Scanner")
    print(Fore.CYAN + "=" * 40)

def handle_arp_spoof():
    """Handle ARP spoofing module."""
    print(Fore.CYAN + "\n[*] ARP Spoofing Module")
    victim_ip = get_valid_ip("Enter Victim IP: ")
    gateway_ip = get_valid_ip("Enter Gateway IP: ")
    print(Fore.YELLOW + "\nWARNING: MAC randomization only works on Linux systems")
    use_mac_random = input(Fore.YELLOW + "Randomize MAC? (y/n): ").lower() == 'y'
    start_spoof(victim_ip, gateway_ip, use_mac_random)

def handle_packet_sniffer():
    """Handle packet sniffer module."""
    print(Fore.CYAN + "\n[*] Packet Sniffer Module")
    iface = get_valid_interface("Enter interface (e.g., eth0): ")
    start_sniffer(iface)

def handle_network_scanner():
    """Handle network scanner module."""
    print(Fore.CYAN + "\n[*] Network Scanner Module")
    target_subnet = get_valid_subnet("Enter target subnet (e.g., 192.168.1.0/24): ")
    scan_network(target_subnet)

def main():
    """Main function to handle program flow."""
    try:
        print_banner()
        while True:
            choice = input(Fore.YELLOW + "\nSelect a module (1-3) or 'q' to quit: ").lower()
            
            if choice == 'q':
                print(Fore.GREEN + "\n[+] Exiting program...")
                sys.exit(0)
            elif choice == '1':
                handle_arp_spoof()
                break
            elif choice == '2':
                handle_packet_sniffer()
                break
            elif choice == '3':
                handle_network_scanner()
                break
            else:
                print(Fore.RED + "[!] Invalid choice. Please select 1-3 or 'q'")

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
