# File: dashboard.py

import tkinter as tk
from tkinter import scrolledtext, messagebox
from threading import Thread
import socket
import subprocess
import re
import os
from core.arp_spoofer import start_spoof
from core.packet_sniffer import start_sniffer
from core.network_scanner import scan_network

class MegadriodMITMGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Megadriod MITM Toolkit")
        self.root.geometry("700x500")

        # Entry for Victim IP
        tk.Label(root, text="Victim IP:").grid(row=0, column=0, sticky='w')
        self.victim_ip = tk.Entry(root)
        self.victim_ip.grid(row=0, column=1)

        # Entry for Gateway IP
        tk.Label(root, text="Gateway IP:").grid(row=1, column=0, sticky='w')
        self.gateway_ip = tk.Entry(root)
        self.gateway_ip.grid(row=1, column=1)

        # Entry for Network Subnet
        tk.Label(root, text="Network Subnet:").grid(row=2, column=0, sticky='w')
        self.network_subnet = tk.Entry(root)
        self.network_subnet.grid(row=2, column=1)

        # Buttons
        tk.Button(root, text="Start ARP Spoof", command=self.start_arp_spoof).grid(row=3, column=0, pady=5)
        tk.Button(root, text="Start Packet Sniffer", command=self.start_packet_sniffer).grid(row=3, column=1, pady=5)
        tk.Button(root, text="Start Network Scan", command=self.start_network_scan).grid(row=3, column=2, pady=5)
        tk.Button(root, text="Auto Detect Network", 
         command=self.detect_network).grid(row=3, column=3, pady=5)

        # Log display area
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.log_area.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

        # Auto-detect network info
        self.detect_network()

    def log(self, msg):
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)

    def start_arp_spoof(self):
        vip = self.victim_ip.get()
        gip = self.gateway_ip.get()
        if not vip or not gip:
            messagebox.showerror("Input Error", "Please enter Victim IP and Gateway IP.")
            return
        self.log("[*] Starting ARP Spoof...")
        # Run in a separate thread to keep UI responsive
        Thread(target=start_spoof, args=(vip, gip, False), daemon=True).start()

    def start_packet_sniffer(self):
        """Handle packet sniffer start with interface detection."""
        iface = self.get_default_iface()
        if not iface:
            messagebox.showerror("Error", "Could not determine default interface")
            return
            
        self.log(f"[*] Starting Packet Sniffer on {iface}")
        Thread(target=start_sniffer, args=(iface,), daemon=True).start()
    
    def get_default_iface(self):
        """Detect the default network interface name."""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True)
                match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+\d+\s+(\w+)', result.stdout)
                if match:
                    return match.group(2)
                # Fallback: try using ipconfig
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                match = re.search(r'Adapter ([^:]+):', result.stdout)
                if match:
                    return match.group(1).strip()
            else:  # Linux/Unix
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                match = re.search(r'default via [\d.]+ dev (\w+)', result.stdout)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None

    def start_network_scan(self):
        target = self.network_subnet.get()
        if not target:
            messagebox.showerror("Input Error", "Please enter a Network Subnet.")
            return
        self.log(f"[*] Scanning network {target} ...")
        Thread(target=self._scan_and_log, args=(target,), daemon=True).start()

    def _scan_and_log(self, target):
        devices = scan_network(target)
        for d in devices:
            self.log(f"Found Device - IP: {d['ip']} MAC: {d['mac']}")

    def get_network_info(self):
        """Get network information including gateway IP and subnet."""
        try:
            if os.name == 'nt':  # Windows
                # Get default gateway
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                gateway = re.search(r'Default Gateway.*: ([\d.]+)', result.stdout)
                gateway_ip = gateway.group(1) if gateway else ''
                
                # Get subnet
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                subnet = re.search(r'Subnet Mask.*: ([\d.]+)', result.stdout)
                subnet_mask = subnet.group(1) if subnet else ''
                
                # Get IP address
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                network = f"{local_ip.rsplit('.', 1)[0]}.0/24"  # Assuming /24 subnet
                
                return gateway_ip, network
                
            else:  # Linux/Unix
                # Get default gateway
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                gateway = re.search(r'default via ([\d.]+)', result.stdout)
                gateway_ip = gateway.group(1) if gateway else ''
                
                # Get subnet
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                network = re.search(r'inet ([\d.]+/\d{2})', result.stdout)
                network_addr = network.group(1) if network else ''
                
                return gateway_ip, network_addr
                
        except Exception as e:
            self.log(f"[!] Error getting network info: {str(e)}")
            return '', ''

    def detect_network(self):
        """Auto-detect and fill network information."""
        gateway_ip, network = self.get_network_info()
        
        if gateway_ip:
            self.gateway_ip.delete(0, tk.END)
            self.gateway_ip.insert(0, gateway_ip)
            self.log(f"[+] Detected Gateway IP: {gateway_ip}")
        
        if network:
            self.network_subnet.delete(0, tk.END)
            self.network_subnet.insert(0, network)
            self.log(f"[+] Detected Network: {network}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MegadriodMITMGUI(root)
    root.mainloop()
