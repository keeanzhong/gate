"""Publish a credential-free, Worker-specific CFNext ingress source."""
import os
from pathlib import Path

import requests

from edge_health import is_cf_ipv4, validated_edge_hosts
from vpngate import EDGE_HOSTS, OPTIMAL_API, fetch_optimal_api_endpoints

PREVIOUS_URL = 'https://keeanzhong.github.io/gate/cfnext-ingress.txt'


def parse_published(value):
    entries = [line.strip().split('#', 1)[0] for line in value.splitlines() if line.strip()]
    if not entries or len(entries) > 12:
        raise ValueError('Invalid prior CFNext feed size')
    if not all(e.endswith(':443') and is_cf_ipv4(e[:-4]) for e in entries):
        raise ValueError('Prior CFNext feed must contain only Cloudflare IPv4:443')
    return list(dict.fromkeys(entries))


def build(worker_host):
    # Include known CF addresses as seeds, but never publish without two upgrades.
    candidates = EDGE_HOSTS + fetch_optimal_api_endpoints(OPTIMAL_API)
    candidates += ['104.17.152.26:443', '104.18.43.26:443', '172.64.144.230:443']
    return validated_edge_hosts(candidates, worker_host, limit=6)


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
