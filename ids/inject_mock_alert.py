#!/usr/bin/env python3
"""
Appends a synthetic Suricata alert event to eve.json for demo purposes.
Run via cron when no real attacks are occurring.
"""

import json
import random
from datetime import datetime, timezone

EVE_LOG = '/var/log/suricata/eve.json'
DEST_IP = '10.128.0.2'

SIGNATURES = [
    (2001219,  'ET SCAN Potential SSH Scan',                                    'Attempted Information Leak',              2),
    (2024364,  'ET SQL SQL Generic SELECT Statement',                           'Attempted Information Leak',              1),
    (2006380,  'ET WEB_SERVER PHP Easter Egg Information Disclosure',           'Web Application Attack',                  2),
    (2001569,  'ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce', 'Attempted Administrator Privilege Gain', 1),
    (2019234,  'ET SCAN Rapid7 Nexpose Scanner',                               'Web Application Attack',                  2),
    (2101411,  'GPL ATTACK_RESPONSE id check returned root',                   'Potentially Bad Traffic',                  1),
    (2008578,  'ET POLICY Incoming Basic Auth Base64 HTTP Password unencrypted','Attempted Administrator Privilege Gain',  2),
    (2013028,  'ET WEB_SERVER SQL Injection SELECT FROM',                       'Web Application Attack',                  1),
    (2210054,  'SURICATA HTTP unable to match response to request',             'Generic Protocol Command Decode',          3),
    (2009582,  'ET SCAN Nmap Scripting Engine User-Agent Detected',            'Web Application Attack',                  2),
]

SOURCE_IPS = [
    '45.33.32.156', '104.131.0.69', '198.20.69.74',
    '89.248.167.131', '185.220.101.47', '92.118.160.11',
    '194.165.16.11', '172.104.251.200', '167.94.138.60',
]


def inject():
    sig_id, sig_name, category, severity = random.choice(SIGNATURES)
    src_ip = random.choice(SOURCE_IPS)

    event = {
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') +
                     f'{datetime.now().microsecond // 1000:03d}+0000',
        'flow_id': random.randint(1_000_000_000, 9_999_999_999),
        'event_type': 'alert',
        'src_ip': src_ip,
        'src_port': random.randint(1024, 65535),
        'dest_ip': DEST_IP,
        'dest_port': random.choice([80, 443, 22]),
        'proto': 'TCP',
        'alert': {
            'action': 'allowed',
            'gid': 1,
            'signature_id': sig_id,
            'rev': 5,
            'signature': sig_name,
            'category': category,
            'severity': severity,
        },
    }

    with open(EVE_LOG, 'a') as f:
        f.write(json.dumps(event) + '\n')

    print(f'Injected: [{src_ip}] {sig_name}')


if __name__ == '__main__':
    inject()
