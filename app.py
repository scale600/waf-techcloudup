import json
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

ALERTS_FILE  = os.environ.get('ALERTS_FILE',  '/opt/waf-demo/alerts.json')
NETWORK_FILE = os.environ.get('NETWORK_FILE', '/opt/waf-demo/network_events.json')
IDS_API_KEY  = os.environ.get('IDS_API_KEY',  '')
MAX_ALERTS   = 50
MAX_NETWORK  = 100


def _load_alerts():
    try:
        with open(ALERTS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_alerts(alerts):
    with open(ALERTS_FILE, 'w') as f:
        json.dump(alerts, f)


def _load_network():
    try:
        with open(NETWORK_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_network(events):
    with open(NETWORK_FILE, 'w') as f:
        json.dump(events, f)


@app.route('/echo', methods=['GET', 'POST'])
def echo():
    query = request.args.get('q', '') or (request.get_json(silent=True) or {}).get('q', '')
    return jsonify({'status': 'safe', 'input': query, 'message': 'Safe request — no threats detected'})


@app.route('/health')
def health():
    return jsonify({'status': 'ok'})


@app.route('/api/ingest', methods=['POST'])
def ingest():
    if request.headers.get('X-API-Key') != IDS_API_KEY or not IDS_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    alerts = _load_alerts()
    data['received_at'] = datetime.now(timezone.utc).isoformat()
    alerts.insert(0, data)
    alerts = alerts[:MAX_ALERTS]
    _save_alerts(alerts)

    return jsonify({'status': 'ok', 'count': len(alerts)}), 201


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = _load_alerts()
    last_updated = alerts[0].get('received_at') if alerts else None
    return jsonify({'alerts': alerts, 'last_updated': last_updated})


@app.route('/api/network-events', methods=['POST'])
def network_ingest():
    if request.headers.get('X-API-Key') != IDS_API_KEY or not IDS_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    events = _load_network()
    data['received_at'] = datetime.now(timezone.utc).isoformat()
    events.insert(0, data)
    events = events[:MAX_NETWORK]
    _save_network(events)

    return jsonify({'status': 'ok', 'count': len(events)}), 201


@app.route('/api/network-events', methods=['GET'])
def get_network_events():
    events = _load_network()
    last_updated = events[0].get('received_at') if events else None
    return jsonify({'events': events, 'last_updated': last_updated})


if __name__ == '__main__':
    app.run()
