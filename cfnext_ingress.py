"""Publish a credential-free, Worker-specific CFNext ingress source."""
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import socket
import ssl
import time

import requests

from edge_health import is_cf_ipv4, candidate_addresses
from vpngate import EDGE_HOSTS, OPTIMAL_API, fetch_optimal_api_endpoints

PREVIOUS_URL = 'https://keeanzhong.github.io/gate/cfnext-ingress.txt'
ROOT_RESPONSE_SHA256 = '60dd610a74e2e7ef7d5eb8fe04f4b414d63e6932a09f7860a69a9549eae361b4'
USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36')


def probe_public_root(address, worker_host):
    # CFNext requires the private VLESS path for WebSocket upgrades. Never copy
    # that credential into a public workflow. Verify its exact public response
    # here; authenticated end-to-end transfers are a separate local acceptance.
    started = time.monotonic()
    with socket.create_connection((address, 443), timeout=5) as tcp:
        with ssl.create_default_context().wrap_socket(tcp, server_hostname=worker_host) as tls:
            tls.settimeout(5)
            tls.sendall((f'GET / HTTP/1.1\r\nHost: {worker_host}\r\nUser-Agent: {USER_AGENT}\r\n'
                         'Accept: text/html\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(65536)
            if response.status != 200 or hashlib.sha256(body).hexdigest() != ROOT_RESPONSE_SHA256:
                raise ValueError('Unexpected CFNext public root response')
    return round((time.monotonic() - started) * 1000)


def parse_published(value):
    entries = [line.strip().split('#', 1)[0] for line in value.splitlines() if line.strip()]
    if not entries or len(entries) > 12:
        raise ValueError('Invalid prior CFNext feed size')
    if not all(e.endswith(':443') and is_cf_ipv4(e[:-4]) for e in entries):
        raise ValueError('Prior CFNext feed must contain only Cloudflare IPv4:443')
    return list(dict.fromkeys(entries))


def build(worker_host):
    if not worker_host or any(c in worker_host for c in '/:@\r\n '):
        raise ValueError('CFNEXT_SNI must name the actual Worker')
    # Include known CF addresses as seeds, but never publish without two upgrades.
    candidates = EDGE_HOSTS + fetch_optimal_api_endpoints(OPTIMAL_API)
    candidates += ['104.17.152.26:443', '104.18.43.26:443', '172.64.144.230:443']
    def resolve(endpoint):
        try:
            return candidate_addresses(endpoint)
        except (ValueError, OSError, requests.RequestException):
            return []
    with ThreadPoolExecutor(max_workers=8) as pool:
        addresses = sorted({a for values in pool.map(resolve, candidates) for a in values})
    def check(address):
        try:
            return address, max(probe_public_root(address, worker_host),
                                probe_public_root(address, worker_host))
        except (ValueError, OSError, ssl.SSLError, http.client.HTTPException):
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        healthy = [r for r in pool.map(check, addresses) if r]
    healthy.sort(key=lambda item: (item[1], item[0]))
    if not healthy:
        raise RuntimeError('No verified CFNext public ingress; preserve previous feed')
    return [f'{address}:443' for address, latency in healthy[:6]]


def publish(output, worker_host, allow_previous=True):
    output = Path(output)
    try:
        entries = build(worker_host)
        preserved = False
    except (OSError, ValueError, RuntimeError, requests.RequestException):
        if not allow_previous:
            raise
        # The two projects fail independently: retain the last CFNext publication
        # rather than synthesize an unchecked pool or block a valid HomeIP update.
        response = requests.get(PREVIOUS_URL, timeout=15)
        response.raise_for_status()
        entries = parse_published(response.text)
        preserved = True
    text = '\n'.join(f'{entry}#CFNext-{i:02d}' for i, entry in enumerate(entries, 1)) + '\n'
    parse_published(text)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding='utf-8')
    return {'count': len(entries), 'preserved_previous': preserved, 'ingress': entries}


if __name__ == '__main__':
    import json
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else 'public/cfnext-ingress.txt'
    print(json.dumps(publish(output, os.environ.get('CFNEXT_SNI', ''),
                             allow_previous=os.environ.get('PREFLIGHT_ONLY') != '1')))
