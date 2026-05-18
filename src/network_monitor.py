"""
Network Monitor for Yoda Voice Agent
Refactored from nsm_network_scanner.py for MCP integration
Provides proactive network monitoring with event-driven alerts
"""

import threading
import time
import socket
import requests
from queue import Queue
from typing import Optional, Dict, List
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1


class NetworkMonitor:
    """Monitors network for device changes and suspicious activity"""

    def __init__(self, interface: str = "en0", subnet: str = "192.168.1.0/24"):
        self.interface = interface
        self.subnet = subnet
        self.scan_delay = 10  # seconds between scans
        self.running = False

        # Track discovered devices
        self.known_devices: Dict[str, Dict] = {}

        # Event queue for voice alerts
        self.event_queue = Queue()

        # Thread-safe lock
        self.lock = threading.Lock()


    def start(self):
        """Start background monitoring"""
        if self.running:
            return

        self.running = True

        # Start ARP scanner thread
        scanner_thread = threading.Thread(
            target=self._arp_scanner,
            daemon=True,
            name="ARP-Scanner"
        )
        scanner_thread.start()

        print(f"[NetworkMonitor] Started on {self.interface} monitoring {self.subnet}")


    def stop(self):
        """Stop background monitoring"""
        self.running = False
        print("[NetworkMonitor] Stopped")


    def get_event(self, timeout: Optional[float] = None) -> Optional[Dict]:
        """Get next event from queue (blocking with optional timeout)"""
        try:
            return self.event_queue.get(timeout=timeout)
        except:
            return None


    def _arp_scanner(self):
        """Continuously scan subnet for devices"""
        scan_count = 0

        while self.running:
            try:
                scan_count += 1

                # Create ARP request for entire subnet
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)

                # Send and receive responses
                answered, _ = srp(arp, iface=self.interface, timeout=5, verbose=0)

                # Process responses
                for sent, recv in answered:
                    ip = recv.psrc
                    mac = recv.hwsrc

                    # Check if this is a new device
                    if ip not in self.known_devices:
                        self._handle_new_device(ip, mac)
                    else:
                        # Update last seen time
                        with self.lock:
                            self.known_devices[ip]["last_seen"] = time.time()
                            # If device was offline, mark back online
                            if self.known_devices[ip]["status"] == "offline":
                                self._handle_device_online(ip)

                # Check for devices that went offline
                self._check_offline_devices()

                # Wait before next scan
                time.sleep(self.scan_delay)

            except Exception as e:
                print(f"[NetworkMonitor] Error in ARP scanner: {e}")
                time.sleep(5)


    def _handle_new_device(self, ip: str, mac: str):
        """Handle discovery of new device"""
        # Get additional info
        hostname = self._get_hostname(ip)
        vendor = self._get_vendor(mac)

        # Store device info
        with self.lock:
            self.known_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "status": "online",
                "first_seen": time.time(),
                "last_seen": time.time()
            }

        # Queue event for voice alert
        event = {
            "type": "device_join",
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "timestamp": time.time()
        }
        self.event_queue.put(event)

        print(f"[NetworkMonitor] New device: {ip} ({hostname}) - {vendor}")


    def _handle_device_online(self, ip: str):
        """Handle device coming back online"""
        with self.lock:
            device = self.known_devices[ip]
            device["status"] = "online"

        event = {
            "type": "device_online",
            "ip": ip,
            "hostname": device["hostname"],
            "timestamp": time.time()
        }
        self.event_queue.put(event)

        print(f"[NetworkMonitor] Device back online: {ip} ({device['hostname']})")


    def _check_offline_devices(self):
        """Check for devices that haven't been seen recently"""
        current_time = time.time()
        offline_threshold = self.scan_delay * 3  # 3 missed scans

        with self.lock:
            for ip, device in self.known_devices.items():
                if device["status"] == "online":
                    time_since_seen = current_time - device["last_seen"]

                    if time_since_seen > offline_threshold:
                        # Mark as offline
                        device["status"] = "offline"

                        # Queue event
                        event = {
                            "type": "device_offline",
                            "ip": ip,
                            "hostname": device["hostname"],
                            "offline_duration": time_since_seen,
                            "timestamp": current_time
                        }
                        self.event_queue.put(event)

                        print(f"[NetworkMonitor] Device offline: {ip} ({device['hostname']})")


    def _get_hostname(self, ip: str) -> str:
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            # Clean up hostname (remove domain suffix)
            if '.' in hostname:
                hostname = hostname.split('.')[0]
            return hostname
        except:
            return "Unknown"


    def _get_vendor(self, mac: str) -> str:
        """Get vendor for MAC address"""
        try:
            # Try online API first (with timeout)
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=2)

            if response.status_code == 200:
                return response.text.strip()
        except:
            pass

        # Fallback to "Unknown"
        return "Unknown"


    def get_device_list(self) -> List[Dict]:
        """Get list of all known devices"""
        with self.lock:
            return list(self.known_devices.values())


    def get_online_devices(self) -> List[Dict]:
        """Get list of online devices"""
        with self.lock:
            return [d for d in self.known_devices.values() if d["status"] == "online"]


    def get_offline_devices(self) -> List[Dict]:
        """Get list of offline devices"""
        with self.lock:
            return [d for d in self.known_devices.values() if d["status"] == "offline"]


# Example usage
if __name__ == "__main__":
    # Create monitor
    monitor = NetworkMonitor(interface="en0", subnet="192.168.1.0/24")

    # Start monitoring
    monitor.start()

    # Process events
    print("Monitoring network... Press Ctrl+C to stop")
    try:
        while True:
            event = monitor.get_event(timeout=1.0)
            if event:
                print(f"EVENT: {event['type']} - {event}")
    except KeyboardInterrupt:
        monitor.stop()
        print("\\nStopped monitoring")
