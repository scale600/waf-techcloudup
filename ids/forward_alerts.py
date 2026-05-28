#!/usr/bin/env python3
"""
Reads new alert events from Suricata's eve.json and POSTs them to the n8n webhook.
Tracks file position in a state file to avoid re-sending on each run.
"""

import json
import os
import sys
import requests

EVE_LOG = '/var/log/suricata/eve.json'
STATE_FILE = '/opt/ids/state/last_position'
N8N_WEBHOOK = os.environ.get('N8N_WEBHOOK_URL', '')


def get_last_position():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return int(f.read().strip() or 0)
    return 0


def save_position(pos):
    with open(STATE_FILE, 'w') as f:
        f.write(str(pos))


def main():
    if not N8N_WEBHOOK:
        print('ERROR: N8N_WEBHOOK_URL not set in /opt/ids/config.env', file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(EVE_LOG):
        print(f'eve.json not found: {EVE_LOG}', file=sys.stderr)
        sys.exit(1)

    last_pos = get_last_position()
    new_alerts = []

    with open(EVE_LOG, 'r') as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    new_alerts.append(event)
            except json.JSONDecodeError:
                continue
        current_pos = f.tell()

    for alert in new_alerts:
        try:
            requests.post(N8N_WEBHOOK, json=alert, timeout=10)
        except requests.RequestException as e:
            print(f'Failed to POST alert: {e}', file=sys.stderr)

    save_position(current_pos)

    if new_alerts:
        print(f'Forwarded {len(new_alerts)} alert(s)')


if __name__ == '__main__':
    main()
