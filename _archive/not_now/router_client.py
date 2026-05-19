#!/usr/bin/env python3
"""Client for GL.iNet router API"""
import requests
import os

class RouterClient:
    def __init__(self, router_url=None, api_key=None, timeout=10):
        self.url = (router_url or os.getenv("ROUTER_API_URL", "http://192.168.8.1:8888")).rstrip('/')
        self.key = api_key or os.getenv("ROUTER_API_KEY", "change-me")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'X-API-Key': self.key})

    def _get(self, endpoint):
        r = self.session.get(f"{self.url}{endpoint}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_devices(self):
        return self._get('/devices').get('devices', [])

    def get_arp_table(self):
        return self._get('/arp').get('arp_table', [])

    def get_dhcp_leases(self):
        return self._get('/dhcp').get('dhcp_leases', [])

    def get_wireless_clients(self):
        return self._get('/wireless').get('wireless_clients', [])

    def health_check(self):
        try:
            return self._get('/health').get('status') == 'ok'
        except:
            return False

    def get_device_count(self):
        return self._get('/devices').get('count', 0)

    def get_device_by_mac(self, mac):
        mac = mac.upper().strip()
        for d in self.get_devices():
            if d.get('mac', '').upper() == mac:
                return d
        return None

    def get_device_by_ip(self, ip):
        for d in self.get_devices():
            if d.get('ip') == ip:
                return d
        return None

if __name__ == '__main__':
    client = RouterClient()
    print("Health:", "OK" if client.health_check() else "FAILED")
    devices = client.get_devices()
    print(f"\n{len(devices)} devices:")
    for d in devices:
        print(f"  {d.get('hostname', 'Unknown'):20} {d.get('ip', 'N/A'):15} {d.get('mac', 'N/A'):17} [{d.get('state', 'N/A')}]")
