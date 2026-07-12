#!/usr/bin/env python3
"""
scanner.py — local TCP port scan helper for the Sara terminal.

Runs a tiny local HTTP server on http://localhost:5051 with one endpoint:

  GET /scan?host=<ip-or-hostname>&ports=<range-or-list>

    ports examples: "1-1024", "22,80,443", "1-100,443,8080"

Returns JSON: {"host": ..., "open": [{"port": 22, "service": "ssh"}, ...]}

USAGE:
    python3 scanner.py
    (leave it running, then use the `scan` command in the terminal UI)

Only scan hosts/networks you own or have explicit permission to test.
Port scanning networks you don't control may be illegal depending on
your jurisdiction and that network's policies.
"""

import socket
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

PORT = 5051
CONNECT_TIMEOUT = 0.5
MAX_WORKERS = 200
MAX_PORTS_PER_SCAN = 5000  # safety cap so a typo doesn't scan all 65535 slowly


def parse_ports(spec):
    """Parse '22,80,443' or '1-1024' or a mix into a sorted list of ints."""
    ports = set()
    for chunk in spec.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            start, end = int(start), int(end)
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(chunk))
    ports = sorted(p for p in ports if 1 <= p <= 65535)
    return ports[:MAX_PORTS_PER_SCAN]


def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECT_TIMEOUT)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = ''
                return port, service
    except socket.gaierror:
        return None
    except Exception:
        pass
    return None


def scan_host(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for result in pool.map(lambda p: check_port(host, p), ports):
            if result:
                port, service = result
                open_ports.append({"port": port, "service": service})
    return sorted(open_ports, key=lambda x: x["port"])


class ScanHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # allow local HTML file to call this
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != '/scan':
            self._send_json(404, {"error": "not found"})
            return

        qs = parse_qs(parsed.query)
        host = qs.get('host', [''])[0].strip()
        port_spec = qs.get('ports', ['1-1024'])[0].strip()

        if not host:
            self._send_json(400, {"error": "missing host param"})
            return

        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror:
            self._send_json(400, {"error": f"can't resolve host '{host}'"})
            return

        try:
            ports = parse_ports(port_spec)
        except ValueError:
            self._send_json(400, {"error": f"bad ports spec '{port_spec}'"})
            return

        if not ports:
            self._send_json(400, {"error": "no valid ports parsed"})
            return

        open_ports = scan_host(resolved, ports)
        self._send_json(200, {"host": host, "resolved": resolved, "open": open_ports})

    def log_message(self, format, *args):
        print(f"[scanner] {self.address_string()} - {format % args}")


if __name__ == '__main__':
    print(f"Sara port scanner running on http://localhost:{PORT}")
    print("Endpoint: /scan?host=<ip>&ports=<range>  e.g. /scan?host=127.0.0.1&ports=1-1024")
    print("Only scan systems you own or have permission to test.")
    server = HTTPServer(('localhost', PORT), ScanHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()