import glob
import io
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response, send_file

app = Flask(__name__)

# Suppress Flask's default request logs (handled by Nginx)
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

ALERTS_FILE         = os.environ.get('ALERTS_FILE',         '/opt/waf-demo/alerts.json')
NETWORK_FILE        = os.environ.get('NETWORK_FILE',        '/opt/waf-demo/network_events.json')
IDS_API_KEY         = os.environ.get('IDS_API_KEY',         '')
INVESTIGATE_SCRIPT  = os.environ.get('INVESTIGATE_SCRIPT',  '/opt/takedown/investigate.sh')
MAX_ALERTS   = 50
MAX_NETWORK  = 100

# Pre-encode API key as bytes for timing-safe comparison
_IDS_API_KEY_BYTES = IDS_API_KEY.encode('utf-8') if IDS_API_KEY else b''

def _valid_api_key(header_val):
    """Timing-safe API key comparison to prevent timing attacks."""
    if not IDS_API_KEY or not header_val:
        return False
    return secrets.compare_digest(header_val.encode('utf-8'), _IDS_API_KEY_BYTES)

_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
)
_inv = {'ts': 0.0, 'mu': threading.Lock()}
_downloads = {}  # token -> {'tmpdir': path, 'ts': float}
_dl_lock = threading.Lock()


def _cleanup_old_downloads():
    now = time.time()
    with _dl_lock:
        expired = [t for t, v in _downloads.items() if now - v['ts'] > 900]
        for t in expired:
            shutil.rmtree(_downloads.pop(t)['tmpdir'], ignore_errors=True)


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


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/ingest', methods=['POST'])
def ingest():
    if not _valid_api_key(request.headers.get('X-API-Key', '')):
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
    if not _valid_api_key(request.headers.get('X-API-Key', '')):
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


@app.route('/api/investigate/stream')
def investigate_stream():
    domain = request.args.get('domain', '').strip().lower()
    if not domain or not _DOMAIN_RE.match(domain):
        return jsonify({'error': 'Invalid domain format'}), 400

    _cleanup_old_downloads()

    with _inv['mu']:
        elapsed = time.time() - _inv['ts']
        if elapsed < 90:
            wait = int(90 - elapsed)
            return jsonify({'error': f'Please wait {wait}s before starting another investigation.'}), 429
        _inv['ts'] = time.time()

    def generate():
        tmpdir = tempfile.mkdtemp(prefix='inv_')
        registered = False
        try:
            proc = subprocess.Popen(
                [INVESTIGATE_SCRIPT, domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=tmpdir,
                text=True,
                bufsize=1,
            )
            for line in iter(proc.stdout.readline, ''):
                yield f"data: {json.dumps(line.rstrip())}\n\n"
            proc.wait()

            matches = glob.glob(os.path.join(tmpdir, f'{domain}_investigation_*'))
            if matches:
                token = uuid.uuid4().hex[:12]
                with _dl_lock:
                    _downloads[token] = {'tmpdir': tmpdir, 'ts': time.time()}
                registered = True
                yield f"data: {json.dumps({'__done__': True, 'token': token})}\n\n"
            else:
                yield f"data: {json.dumps({'__done__': True})}\n\n"
        except Exception:
            yield f"data: {json.dumps('Error: Investigation failed')}\n\n"
            yield f"data: {json.dumps({'__done__': True})}\n\n"
        finally:
            if not registered:
                shutil.rmtree(tmpdir, ignore_errors=True)

    resp = Response(generate(), mimetype='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'
    return resp


@app.route('/api/investigate/download/<token>')
def investigate_download(token):
    with _dl_lock:
        entry = _downloads.pop(token, None)
    if not entry:
        return jsonify({'error': 'Not found or expired'}), 404

    tmpdir = entry['tmpdir']
    try:
        matches = glob.glob(os.path.join(tmpdir, '*_investigation_*'))
        if not matches:
            return jsonify({'error': 'Investigation files not found'}), 404

        inv_dir = matches[0]
        zip_name = os.path.basename(inv_dir) + '.zip'

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fname in sorted(os.listdir(inv_dir)):
                fpath = os.path.join(inv_dir, fname)
                if os.path.isfile(fpath):
                    zf.write(fpath, arcname=fname)
        buf.seek(0)

        return send_file(
            buf,
            mimetype='application/zip',
            as_attachment=True,
            download_name=zip_name,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    app.run()
