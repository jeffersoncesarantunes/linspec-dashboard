import sqlite3, json, os, uuid, hashlib, time
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', uuid.uuid4().hex)
DB = os.environ.get('LINSPEC_DB', os.path.join(os.path.dirname(__file__), 'data.db'))
DEBUG = os.environ.get('LINSPEC_DEBUG', '').lower() in ('1', 'true', 'yes')
RATE_LIMIT = int(os.environ.get('LINSPEC_RATE_LIMIT', '60'))

_request_times = {}

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.remote_addr or 'unknown'
        now = time.time()
        window = _request_times.get(key, [])
        window = [t for t in window if now - t < 60]
        if len(window) >= RATE_LIMIT:
            return jsonify({'error': 'rate limit exceeded'}), 429
        window.append(now)
        _request_times[key] = window
        return f(*args, **kwargs)
    return decorated

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            kernel TEXT,
            os TEXT,
            total_checks INTEGER DEFAULT 0,
            passed INTEGER DEFAULT 0,
            warned INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            score REAL DEFAULT 0,
            raw_json TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scan_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            check_name TEXT,
            category TEXT,
            status TEXT,
            message TEXT
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            label TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """)

init_db()

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('key')
        if not key:
            return jsonify({'error': 'API key required'}), 401
        with get_db() as conn:
            row = conn.execute("SELECT 1 FROM api_keys WHERE key=?", (key,)).fetchone()
        if not row:
            return jsonify({'error': 'invalid API key'}), 403
        return f(*args, **kwargs)
    return decorated

# --- Landing page subscription ---
@app.route('/api/subscribe', methods=['POST'])
@rate_limit
def subscribe():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    if not name or not email or '@' not in email:
        return redirect(url_for('thank_you', error='Dados invalidos'))
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO subscribers (name, email) VALUES (?, ?)", (name, email))
        return redirect(url_for('thank_you'))
    except sqlite3.IntegrityError:
        return redirect(url_for('thank_you'))

@app.route('/obrigado')
def thank_you():
    return redirect('/obrigado.html')

# --- API: receive scan report ---
@app.route('/api/scan', methods=['POST'])
@rate_limit
@require_api_key
def receive_scan():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'invalid JSON'}), 400

    checks = data.get('checks', data.get('results', []))
    hostname = data.get('hostname', request.remote_addr or 'unknown')
    kernel = data.get('kernel', '')
    os_ = data.get('os', '')

    total = len(checks)
    passed = sum(1 for c in checks if c.get('status') == 'PASS')
    warned = sum(1 for c in checks if c.get('status') == 'WARN')
    failed = sum(1 for c in checks if c.get('status') == 'VULN')
    score = round((passed / total * 100) if total else 0, 1)

    with get_db() as conn:
        cur = conn.execute("""
            INSERT INTO scans (hostname, kernel, os, total_checks, passed, warned, failed, score, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hostname, kernel, os_, total, passed, warned, failed, score, json.dumps(data)))
        scan_id = cur.lastrowid

        for c in checks:
            conn.execute("""
                INSERT INTO scan_checks (scan_id, check_name, category, status, message)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, c.get('check', c.get('name', 'unknown')),
                  c.get('category', 'general'), c.get('status', 'UNKNOWN'),
                  c.get('message', '')))

    return jsonify({'scan_id': scan_id, 'score': score, 'status': 'ok'})

# --- Web Dashboard ---
@app.route('/')
def dashboard():
    with get_db() as conn:
        scans = conn.execute("""
            SELECT id, hostname, kernel, total_checks, passed, warned, failed, score, created_at
            FROM scans ORDER BY created_at DESC LIMIT 50
        """).fetchall()
        stats = conn.execute("""
            SELECT COUNT(*) as total_scans,
                   COALESCE(AVG(score), 0) as avg_score,
                   SUM(passed) as total_passed,
                   SUM(warned) as total_warned,
                   SUM(failed) as total_failed
            FROM scans
        """).fetchone()
        subscriber_count = conn.execute("SELECT COUNT(*) as cnt FROM subscribers").fetchone()['cnt']

    return render_template('dashboard.html', scans=scans, stats=stats,
                          subscriber_count=subscriber_count)

@app.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    with get_db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return "Scan not found", 404
        checks = conn.execute("""
            SELECT check_name, category, status, message
            FROM scan_checks WHERE scan_id=? ORDER BY category, check_name
        """, (scan_id,)).fetchall()
    return render_template('scan_detail.html', scan=scan, checks=checks)

@app.route('/api/scan/<int:scan_id>/raw')
def raw_scan(scan_id):
    with get_db() as conn:
        row = conn.execute("SELECT raw_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify(json.loads(row['raw_json']))

# --- Admin: setup first API key ---
@app.route('/admin/setup')
def admin_setup():
    with get_db() as conn:
        existing = conn.execute("SELECT COUNT(*) as cnt FROM api_keys").fetchone()['cnt']
        if existing == 0:
            key = 'linspec-' + uuid.uuid4().hex[:16]
            conn.execute("INSERT INTO api_keys (key, label) VALUES (?, ?)", (key, 'auto-generated'))
            return f"API Key gerada: <code>{key}</code><br> Use no header X-API-Key ao enviar scans."
        return "API Key ja existe. Crie manualmente no banco se necessario."

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=DEBUG)
