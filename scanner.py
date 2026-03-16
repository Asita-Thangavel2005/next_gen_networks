import socket
import subprocess
import platform
import re
import json
from datetime import datetime
import threading

# Try to import scapy, fall back to basic scanning if not available
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Known MAC prefixes for device type detection
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:11": "Google",
    "f4:f5:d8": "Google",
    "ac:37:43": "HTC",
    "00:23:76": "HTC",
    "3c:5a:b4": "Google",
    "f8:8f:ca": "Apple",
    "00:17:f2": "Apple",
    "3c:07:54": "Apple",
}

known_devices = {}  # MAC -> device info
whitelisted_macs = set()
rogue_alerts = []


def get_local_ip():
    """Get the local machine's IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_ip_range():
    """Get the IP range to scan based on local IP."""
    local_ip = get_local_ip()
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1/24"


def get_hostname(ip):
    """Resolve hostname from IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def guess_device_type(mac, hostname):
    """Guess device type from MAC vendor or hostname."""
    mac_upper = mac.upper()
    for prefix, vendor in MAC_VENDORS.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    hostname_lower = hostname.lower()
    if any(k in hostname_lower for k in ["phone", "android", "iphone"]):
        return "Phone"
    if any(k in hostname_lower for k in ["laptop", "pc", "desktop", "windows"]):
        return "Computer"
    if any(k in hostname_lower for k in ["router", "gateway"]):
        return "Router"
    return "Unknown Device"


def scan_with_scapy(ip_range):
    """Scan network using ARP via scapy."""
    devices = []
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            mac = received.hwsrc
            ip = received.psrc
            hostname = get_hostname(ip)
            device_type = guess_device_type(mac, hostname)
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "type": device_type,
                "status": "Online",
                "last_seen": datetime.now().strftime("%H:%M:%S")
            })
    except Exception as e:
        print(f"Scapy scan error: {e}")
    return devices


def scan_with_ping(ip_range_base):
    """Fallback: ping sweep to find active devices."""
    devices = []
    active_ips = []

    def ping_ip(ip):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, "1", "-w", "500", ip] if platform.system().lower() == "windows" else ["ping", param, "1", "-W", "1", ip]
        try:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                active_ips.append(ip)
        except Exception:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{ip_range_base}.{i}"
        t = threading.Thread(target=ping_ip, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    for ip in active_ips:
        hostname = get_hostname(ip)
        devices.append({
            "ip": ip,
            "mac": "N/A",
            "hostname": hostname,
            "type": "Unknown Device",
            "status": "Online",
            "last_seen": datetime.now().strftime("%H:%M:%S")
        })

    return devices


def scan_network():
    """Main scan function - uses scapy if available, else ping."""
    global known_devices, rogue_alerts

    local_ip = get_local_ip()
    parts = local_ip.split(".")
    ip_base = f"{parts[0]}.{parts[1]}.{parts[2]}"
    ip_range = f"{ip_base}.1/24"

    if SCAPY_AVAILABLE:
        devices = scan_with_scapy(ip_range)
    else:
        devices = scan_with_ping(ip_base)

    # Add self
    self_entry = {
        "ip": local_ip,
        "mac": "self",
        "hostname": socket.gethostname(),
        "type": "This Device",
        "status": "Online",
        "last_seen": datetime.now().strftime("%H:%M:%S")
    }
    devices.insert(0, self_entry)

    # Check for rogue devices
    for device in devices:
        mac = device["mac"]
        if mac != "self" and mac != "N/A":
            if mac not in whitelisted_macs and len(whitelisted_macs) > 0:
                alert = {
                    "ip": device["ip"],
                    "mac": mac,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "message": f"Unknown device detected: {device['ip']}"
                }
                if not any(a["mac"] == mac for a in rogue_alerts):
                    rogue_alerts.append(alert)

        # Update known devices
        known_devices[mac] = device

    return devices


def whitelist_all_current():
    """Whitelist all currently known devices."""
    global whitelisted_macs
    for mac in known_devices:
        whitelisted_macs.add(mac)
    return list(whitelisted_macs)


def get_rogue_alerts():
    return rogue_alerts


def clear_alerts():
    global rogue_alerts
    rogue_alerts = []