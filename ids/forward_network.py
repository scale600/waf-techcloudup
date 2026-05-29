#!/usr/bin/env python3
"""
Reads new DNS and HTTP events from eve.json and POSTs them directly
to the Flask /api/network-events endpoint (bypasses n8n — too high volume for Slack).
"""

import json
import os
import sys
import requests

EVE_LOG    = '/var/log/suricata/eve.json'
STATE_FILE = '/opt/ids/state/network_position'
FLASK_API  = 'http://localhost:5000'
API_KEY    = os.environ.get('IDS_API_KEY', '')
MAX_PER_RUN = 50


def get_last_position():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return int(f.read().strip() or 0)
    return 0


def save_position(pos):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        f.write(str(pos))


def should_include(event):
    t = event.get('event_type')
    if t == 'dns':
        return event.get('dns', {}).get('type') == 'query'
    return t == 'http'


def main():
    if not API_KEY:
        print('ERROR: IDS_API_KEY not set', file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(EVE_LOG):
        sys.exit(0)

    last_pos = get_last_position()
    collected = []

    with open(EVE_LOG) as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if should_include(event):
                    collected.append(event)
            except json.JSONDecodeError:
                continue
        current_pos = f.tell()

    events = collected[-MAX_PER_RUN:]
    headers = {'X-API-Key': API_KEY, 'Content-Type': 'application/json'}
    sent = 0
    for event in events:
        try:
            r = requests.post(
                f'{FLASK_API}/api/network-events',
                json=event, headers=headers, timeout=5
            )
            if r.status_code == 201:
                sent += 1
        except requests.RequestException as e:
            print(f'Failed to POST event: {e}', file=sys.stderr)

    save_position(current_pos)
    if sent:
        print(f'Forwarded {sent} network event(s)')


if __name__ == '__main__':
    main()
