"""Admit only Cloudflare ingress addresses that route to the intended Worker.

The TLS and WebSocket probe checks ingress, not residential exit throughput.
No subscription credential is needed or sent by this check.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

import requests

# Published Cloudflare proxy ranges: https://www.cloudflare.com/ips-v4/
CF_RANGES = tuple(ipaddress.ip_network(value) for value in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'))
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def is_cf_ipv4(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 4 and any(ip in network for network in CF_RANGES)
    except ValueError:
        return False


def candidate_addresses(endpoint):
    parsed = urlsplit('//' + endpoint)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        return []
    host = parsed.hostname
    if not host or (parsed.port or 443) != 443:
        return []
    try:
        address = ipaddress.ip_address(host)
        return [str(address)] if is_cf_ipv4(str(address)) else []
    except ValueError:
        pass
    response = requests.get('https://cloudflare-dns.com/dns-query',
                            params={'name': host, 'type': 'A'},
                            headers={'Accept': 'application/dns-json'}, timeout=6)
    response.raise_for_status()
    answers = response.json()
    if answers.get('Status') != 0:
        return []
    return sorted({a['data'] for a in answers.get('Answer', [])
                   if a.get('type') == 1 and is_cf_ipv4(a.get('data', ''))})[:3]


def websocket_headers_ok(raw, nonce):
    if b'\r\n\r\n' not in raw:
        return False
    head = raw.split(b'\r\n\r\n', 1)[0].decode('latin-1')
    lines = head.split('\r\n')
    if lines[0].split()[:2] != ['HTTP/1.1', '101']:
        return False
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            name, value = line.split(':', 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(hashlib.sha1((nonce + WS_GUID).encode()).digest()).decode()
    return (headers.get('upgrade', '').lower() == 'websocket'
            and 'upgrade' in [token.strip() for token in headers.get('connection', '').lower().split(',')]
            and headers.get('sec-websocket-accept') == expected)


def probe_ingress(address, worker_host):
    started = time.monotonic()
    nonce = base64.b64encode(os.urandom(16)).decode()
    # Verify the actual Worker hostname, not a certificate from an unrelated site.
    context = ssl.create_default_context()
    bind = os.environ.get('EDGE_BIND_ADDRESS')
    source = (bind, 0) if bind else None
    with socket.create_connection((address, 443), timeout=5, source_address=source) as tcp:
        with context.wrap_socket(tcp, server_hostname=worker_host) as tls:
            tls.settimeout(5)
            request = (f'GET / HTTP/1.1\r\nHost: {worker_host}\r\n'
                       'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                       f'Sec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\n\r\n')
            tls.sendall(request.encode())
            raw = b''
            while b'\r\n\r\n' not in raw and len(raw) < 16384:
                chunk = tls.recv(min(4096, 16384 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if not websocket_headers_ok(raw, nonce):
                raise ValueError('Intended Worker did not accept WebSocket upgrade')
            # Masked normal WebSocket close. Never open an outbound tunnel.
            mask = os.urandom(4)
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(b'\x03\xe8'))
            tls.sendall(b'\x88\x82' + mask + payload)
    return round((time.monotonic() - started) * 1000)


def validated_edge_hosts(endpoints, worker_host, limit=6):
    if not worker_host or any(c in worker_host for c in '/:@\r\n '):
        raise ValueError('EDGE_SNI must be the intended Worker hostname')

    def resolve(endpoint):
        try:
            return candidate_addresses(endpoint)
        except (ValueError, OSError, requests.RequestException):
            return []

    with ThreadPoolExecutor(max_workers=8) as pool:
        candidates = sorted({address for values in pool.map(resolve, endpoints) for address in values})

    def check(address):
        try:
            first = probe_ingress(address, worker_host)
            second = probe_ingress(address, worker_host)
            return address, max(first, second)
        except (ValueError, OSError, ssl.SSLError):
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        healthy = [r for r in pool.map(check, candidates) if r is not None]
    healthy.sort(key=lambda item: (item[1], item[0]))
    if not healthy:
        raise RuntimeError('No verified Worker ingress; preserve the last published feed')
    return [f'{address}:443' for address, latency in healthy[:limit]]
