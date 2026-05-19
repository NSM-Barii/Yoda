#!/usr/bin/env python3
"""Lightweight HTTP API for GL.iNet router - exposes network device info"""
import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os
import time

API_KEY = os.getenv("ROUTER_API_KEY", "change-me")
PORT = int(os.getenv("ROUTER_API_PORT", "8888"))

class RouterAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _check_auth(self):
        query = parse_qs(urlparse(self.path).query)
        return query.get('api_key', [''])[0] == API_KEY or self.headers.get('X-API-Key') == API_KEY

    def _read_arp(self):
        devices = []
        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 6 and p[3] != '00:00:00:00:00:00':
                        devices.append({'ip': p[0], 'mac': p[3].upper(), 'interface': p[5], 'state': 'REACHABLE' if p[2] == '0x2' else 'INCOMPLETE'})
        except Exception as e:
            print(f"ARP error: {e}")
        return devices

    def _read_dhcp(self):
        leases = []
        try:
            with open('/tmp/dhcp.leases') as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 5:
                        leases.append({'timestamp': int(p[0]), 'mac': p[1].upper(), 'ip': p[2], 'hostname': p[3] if p[3] != '*' else None})
        except:
            pass
        return leases

    def _read_wireless(self):
        clients = []
        try:
            r = subprocess.run(['ubus', 'call', 'hostapd.wlan0', 'get_clients'], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                for mac, info in data.get('clients', {}).items():
                    clients.append({'mac': mac.upper(), 'signal': info.get('signal'), 'connected_time': info.get('connected_time')})
        except:
            pass
        return clients

    def _merge_devices(self):
        devices = {}
        for d in self._read_arp():
            devices[d['mac']] = d
        for l in self._read_dhcp():
            mac = l['mac']
            if mac in devices:
                devices[mac].update({'hostname': l['hostname'], 'dhcp_timestamp': l['timestamp']})
            else:
                devices[mac] = {'ip': l['ip'], 'mac': mac, 'hostname': l['hostname'], 'state': 'OFFLINE'}
        for w in self._read_wireless():
            if w['mac'] in devices:
                devices[w['mac']]['wireless'] = {'signal': w['signal'], 'connected_time': w['connected_time']}
        return list(devices.values())

    def do_GET(self):
        if not self._check_auth():
            return self._send_json({'error': 'Unauthorized'}, 401)
        path = urlparse(self.path).path
        ts = int(time.time())
        if path == '/devices':
            d = self._merge_devices()
            self._send_json({'timestamp': ts, 'count': len(d), 'devices': d})
        elif path == '/arp':
            self._send_json({'timestamp': ts, 'arp_table': self._read_arp()})
        elif path == '/dhcp':
            self._send_json({'timestamp': ts, 'dhcp_leases': self._read_dhcp()})
        elif path == '/wireless':
            self._send_json({'timestamp': ts, 'wireless_clients': self._read_wireless()})
        elif path == '/health':
            self._send_json({'status': 'ok', 'timestamp': ts})
        else:
            self._send_json({'error': 'Not found', 'endpoints': ['/devices', '/arp', '/dhcp', '/wireless', '/health']}, 404)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

if __name__ == '__main__':
    server = HTTPServer(("0.0.0.0", PORT), RouterAPIHandler)
    print(f"Router API on port {PORT} | Key: {API_KEY}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
