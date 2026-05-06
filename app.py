import base64
import os
import json
import datetime
import urllib.request
import urllib.error
import time
import threading
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps

from echo_reporter import install_reporter  # Echo monitoring

# ── Safe URL helper — only allow https:// (blocks file://, ftp://, SSRF) ────
def _safe_urlopen(req_or_url, timeout=10):
    url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
    if not url.startswith('https://'):
        raise ValueError(f'Blocked non-https URL: {url}')
    return urllib.request.urlopen(req_or_url, timeout=timeout)

app = Flask(__name__)

def _get_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    data_dir = os.environ.get('RAILWAY_DATA_DIR') or os.environ.get('DATA_DIR') or '/data'
    key_file = os.path.join(data_dir, 'secret_key')
    try:
        os.makedirs(data_dir, exist_ok=True)
        if os.path.exists(key_file):
            with open(key_file) as f:
                key = f.read().strip()
            if key:
                return key
        import secrets as _sec
        key = _sec.token_hex(32)
        with open(key_file, 'w') as f:
            f.write(key)
        return key
    except Exception:
        import secrets as _sec
        return _sec.token_hex(32)

install_reporter(app, "EcDash")

# ── Stable secret key (survives redeploys) ────────────────────────────────────
_SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not _SECRET_KEY:
    _DATA_DIR = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', os.path.dirname(__file__))
    _KEY_FILE = os.path.join(_DATA_DIR, '.secret_key')
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE) as _f: _SECRET_KEY = _f.read().strip()
        if not _SECRET_KEY:
            import secrets as _s
            _SECRET_KEY = _s.token_hex(32)
            with open(_KEY_FILE, 'w') as _f: _f.write(_SECRET_KEY)
    except Exception:
        import secrets as _s
        _SECRET_KEY = _s.token_hex(32)
app.secret_key = _get_secret_key()




# ── Session config ────────────────────────────────────────────────────────────
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['SESSION_COOKIE_SECURE']     = False  # Railway edge handles TLS

# ── CSRF protection ───────────────────────────────────────────────────────────────
def _get_csrf_token():
    """Generate (or retrieve) a per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = _secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf():
    """Return True if the CSRF token in the request matches the session token."""
    token = (request.form.get('csrf_token')
             or request.headers.get('X-CSRF-Token', ''))
    return bool(token and token == session.get('csrf_token', ''))

# Expose to all Jinja2 templates as {{ csrf_token() }}
app.jinja_env.globals['csrf_token'] = _get_csrf_token


# In-memory rate limiter
_rate_store: dict = {}

def rate_limit(key, max_calls=30, window=60):
    """Return True if key has exceeded max_calls within window seconds."""
    now = time.time()
    calls = [t for t in _rate_store.get(key, []) if now - t < window]
    _rate_store[key] = calls
    if len(calls) >= max_calls:
        return True
    _rate_store[key].append(now)
    return False


# ── Scanner / bot sink paths — return 410 Gone to reduce noise ─────────────────
_SINK_PATHS = frozenset([
    '/api', '/admin', '/_next/', '/en/', '/login',
    '/wp-admin', '/wp-login', '/xmlrpc.php', '/wordpress',
    '/.env', '/config.php', '/setup.php', '/administrator',
    '/phpmyadmin', '/mysql', '/database', '/backup', '/bak',
    '/old/', '/new/', '/test/', '/dev/', '/v1/', '/v2/',
    '/console', '/api-docs', '/swagger', '/graphiql', '/graphql',
    '/favicon.ico', '/sitemap.xml', '/robots.txt',
])

@app.before_request
def _scanner_sink():
    """Drop known scanner bait with 410 Gone before they hit app logic."""
    from flask import abort
    path = request.path.rstrip('/')
    if path in _SINK_PATHS or any(path.startswith(p) for p in [
        '/_next/', '/wp-', '/api ', '/admin/', '/.env',
    ]):
        abort(410)  # Gone — tells scanners to stop hitting this path


@app.before_request
def _csrf_protect():
    """Enforce CSRF on all state-changing requests."""
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if request.path.startswith('/api/'):
            return  # API routes use token auth, skip CSRF
        if not _validate_csrf():
            from flask import abort
            abort(403)

def csrf_required(f):
    """Decorator: reject form POST requests with missing/invalid CSRF token."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST' and not _validate_csrf():
            if request.is_json or request.headers.get('Authorization', ''):
                return f(*args, **kwargs)
            return jsonify({'error': 'CSRF validation failed'}), 403
        return f(*args, **kwargs)
    return decorated

# ── Security headers ─────────────────────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval';"
    )
    return response

# ── Paths ─────────────────────────────────────────────────────────────────────
_DATA_DIR    = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', os.path.dirname(__file__))
_BRAIN_SYNC_TOKEN_FILE = os.path.join(_DATA_DIR if '_DATA_DIR' in dir() else os.path.dirname(__file__), 'brain_sync_token.txt')
_BRAIN_SYNC_TOKEN_HASH = 'a9e68f1e371178e760af52a58920fc7cb7895921f2e513809c22357f10b39ff2'

def _get_brain_sync_token():
    """Return BRAIN_SYNC_TOKEN from env, /data file, or accept by hash comparison."""
    t = os.environ.get('BRAIN_SYNC_TOKEN', '')
    if t:
        return t
    if os.path.exists(_BRAIN_SYNC_TOKEN_FILE):
        return open(_BRAIN_SYNC_TOKEN_FILE).read().strip()
    return ''

def _check_brain_sync_token(provided):
    """Validate a brain sync token — accepts env/file token OR pre-registered hash."""
    import hashlib as _hl2
    if not provided:
        return False
    # Check against env/file token (plain equality)
    expected = _get_brain_sync_token()
    if expected and provided == expected:
        return True
    # Check against pre-registered hash (for fresh deploys before env var is set)
    return _hl2.sha256(provided.encode()).hexdigest() == _BRAIN_SYNC_TOKEN_HASH

CONFIG_FILE  = os.path.join(os.path.dirname(__file__), 'config.json')
CHAT_DB_PATH = os.path.join(_DATA_DIR, 'chat_history.db')

# ── Chat history DB ───────────────────────────────────────────────────────────
def get_chat_db():
    db = sqlite3.connect(CHAT_DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            title     TEXT NOT NULL DEFAULT "New Conversation",
            created   TEXT DEFAULT CURRENT_TIMESTAMP,
            updated   TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
            role            TEXT NOT NULL,
            content         TEXT NOT NULL,
            created         TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
    db.commit()
    return db

def auto_title(first_user_msg):
    """Generate a short title from the first message."""
    t = first_user_msg.strip()[:60]
    if len(first_user_msg) > 60: t += '...'
    return t

TODOS_FILE      = os.path.join(os.path.dirname(__file__), 'todos.json')
TICKETS_FILE    = os.path.join(os.path.dirname(__file__), 'tickets.json')
ECHO_TASKS_FILE = os.path.join(os.path.dirname(__file__), 'echo_tasks.json')
NOTES_FILE      = os.path.join(_DATA_DIR, 'notes.json')  # persists on /data volume

def load_notes():
    if os.path.exists(NOTES_FILE):
        try:
            with open(NOTES_FILE) as f: return json.load(f)
        except: pass
    return []

def save_notes(notes):
    os.makedirs(os.path.dirname(NOTES_FILE), exist_ok=True)
    with open(NOTES_FILE, 'w') as f: json.dump(notes, f, indent=2)



def load_tickets():
    if os.path.exists(TICKETS_FILE):
        try:
            with open(TICKETS_FILE) as f: return json.load(f)
        except: pass
    return []

def save_tickets(tickets):
    with open(TICKETS_FILE, 'w') as f: json.dump(tickets, f, indent=2)

DEFAULT_CONFIG = {
    "photo": "👨‍💻", "name": "Jay Alexander",
    "tagline": "Building the Future with AI & Code",
    "email": "jay@libertyemporium.com", "github": "Liberty-Emporium", "photo_url": ""
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f: return json.load(f)
        except: pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=4)

def load_todos():
    if os.path.exists(TODOS_FILE):
        try:
            with open(TODOS_FILE) as f: return json.load(f)
        except: pass
    return []

def save_todos(todos):
    with open(TODOS_FILE, 'w') as f: json.dump(todos, f, indent=2)

config = load_config()

# ── App settings (model, behavior) ───────────────────────────────────────────
APP_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'app_settings.json')

DEFAULT_APP_SETTINGS = {
    'echo_agent_name': 'EcDash',
    'echo_agent_tagline': 'Your AI operational partner',
    'echo_model': 'anthropic/claude-3.5-haiku',
    'echo_max_tokens': 1024,
    'echo_temperature': 0.7,
}

def load_app_settings():
    if os.path.exists(APP_SETTINGS_FILE):
        try:
            with open(APP_SETTINGS_FILE) as f: return {**DEFAULT_APP_SETTINGS, **json.load(f)}
        except: pass
    return DEFAULT_APP_SETTINGS.copy()

def save_app_settings(s):
    with open(APP_SETTINGS_FILE, 'w') as f: json.dump(s, f, indent=2)


# ── Auth (MUST come before any route that uses @login_required) ───────────────
DASHBOARD_PASSWORD = os.environ.get('DASHBOARD_PASSWORD', 'liberty2026')

def get_dashboard_password():
    """Return dashboard password — config.json override takes priority over env var."""
    stored = load_config().get('dashboard_password', '')
    return stored if stored else DASHBOARD_PASSWORD

import hashlib
import secrets as _secrets

API_TOKENS_FILE = os.path.join(_DATA_DIR, 'api_tokens.json')

def load_api_tokens():
    if os.path.exists(API_TOKENS_FILE):
        try:
            with open(API_TOKENS_FILE) as f: return json.load(f)
        except: pass
    return []

def save_api_tokens(tokens):
    with open(API_TOKENS_FILE, 'w') as f: json.dump(tokens, f, indent=2)

# ── Auto-register permanent chat bearer token on startup ──────────────────────
def _register_permanent_token():
    """Register CHAT_BEARER_TOKEN in api_tokens.json on startup.
    Survives redeploys — no session cookie needed for /chat or /dashboard."""
    import hashlib as _hl
    raw = os.environ.get('CHAT_BEARER_TOKEN', '')
    if not raw:
        return
    token_hash = _hl.sha256(raw.encode()).hexdigest()
    tokens = load_api_tokens()
    if any(t.get('token_hash') == token_hash for t in tokens):
        return
    tokens = [t for t in tokens if t.get('label') != 'chat-permanent']
    tokens.append({
        'token_hash': token_hash,
        'label':      'chat-permanent',
        'expires_at': None,
        'created':    datetime.datetime.utcnow().isoformat(),
    })
    save_api_tokens(tokens)

def _vault_first_run():
    """Ensure vault DB exists and register the ecdash-bridge token as a valid Bearer."""
    import hashlib as _hl
    try:
        db = get_vault_db()
        db.close()
    except Exception:
        pass
    # Register ecdash-bridge token by hash (no plaintext stored here)
    _ECDASH_HASH = '5803387781fc886a228f16c41272f22edf1ccbe085ee19b533aaa8fdda9ee1a8'
    tokens = load_api_tokens()
    if not any(t.get('token_hash') == _ECDASH_HASH for t in tokens):
        tokens = [t for t in tokens if t.get('label') != 'ecdash-bridge']
        tokens.append({
            'token_hash': _ECDASH_HASH,
            'label': 'ecdash-bridge',
            'expires_at': None,
            'created': datetime.datetime.utcnow().isoformat(),
        })
        save_api_tokens(tokens)

def _register_brain_sync_token():
    """Write brain_sync_token.txt to /data — always prefer env var over stale file."""
    raw = os.environ.get('BRAIN_SYNC_TOKEN', '')
    if raw:
        try:
            with open(_BRAIN_SYNC_TOKEN_FILE, 'w') as f:
                f.write(raw)
        except Exception:
            pass
    elif not os.path.exists(_BRAIN_SYNC_TOKEN_FILE):
        pass  # nothing to write

_register_permanent_token()
_vault_first_run()
_register_brain_sync_token()

# ── Password Reset ───────────────────────────────────────────────────────────
RESET_EMAILS   = ['alexanderjay70@gmail.com', 'emporiumandthrift@gmail.com']
_RESET_DB_PATH = None  # set after _DATA_DIR is defined below

def _get_reset_db_path():
    global _RESET_DB_PATH
    if _RESET_DB_PATH is None:
        _RESET_DB_PATH = os.path.join(_DATA_DIR, 'pw_resets.db')
    return _RESET_DB_PATH

def _init_reset_db():
    db = sqlite3.connect(_get_reset_db_path())
    db.execute('''
        CREATE TABLE IF NOT EXISTS pw_resets (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )
    ''')
    db.commit()
    db.close()

_init_reset_db()

def _send_reset_email(token):
    """Send reset link to both recovery emails via Gmail SMTP or Railway SMTP env vars."""
    reset_url = f'https://jay-portfolio-production.up.railway.app/reset-password/{token}'
    subject   = 'EcDash — Password Reset'
    body_html = f'''<div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;background:#030712;color:#f9fafb;padding:32px;border-radius:16px">
  <h2 style="color:#a78bfa;margin-bottom:8px">🔐 EcDash Password Reset</h2>
  <p style="color:#9ca3af;margin-bottom:24px">Click the button below to set a new password. This link expires in <strong>30 minutes</strong>.</p>
  <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;padding:14px 28px;border-radius:10px;text-decoration:none;font-weight:700">Reset My Password</a>
  <p style="color:#6b7280;font-size:.8rem;margin-top:24px">If you didn\'t request this, ignore this email. Your password won\'t change.</p>
  <hr style="border-color:#1f2937;margin:24px 0">
  <p style="color:#4b5563;font-size:.75rem">Or copy this link:<br>{reset_url}</p>
</div>'''

    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASS', '')

    if not smtp_user or not smtp_pass:
        # Log the link so Jay can still reset even without SMTP configured
        app.logger.warning(f'SMTP not configured — reset link: {reset_url}')
        return False

    sent = 0
    for to_addr in RESET_EMAILS:
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = smtp_user
            msg['To']      = to_addr
            msg.attach(MIMEText(body_html, 'html'))
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, to_addr, msg.as_string())
            sent += 1
        except Exception as e:
            app.logger.error(f'Reset email to {to_addr} failed: {e}')
    return sent > 0


def check_bearer_token():
    """Check Authorization: Bearer <token> header. Returns True if valid."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '): return False
    raw = auth[7:].strip()
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    tokens = load_api_tokens()
    now = datetime.datetime.utcnow().isoformat()
    return any(t.get('token_hash') == token_hash and
               (not t.get('expires_at') or t['expires_at'] > now)
               for t in tokens)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Accept bearer token OR session cookie
        if check_bearer_token():
            return f(*args, **kwargs)
        if not session.get('dashboard_auth'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change dashboard password and/or email from the Overseer."""
    data = request.get_json() or {}
    current_pw = data.get('current_password', '')
    new_pw = data.get('new_password', '').strip()
    new_email = data.get('email', None)

    if current_pw != get_dashboard_password():
        return jsonify({'error': 'Current password is incorrect'}), 403

    if new_pw and len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400

    global config
    config = load_config()
    changed = []

    if new_pw:
        config['dashboard_password'] = new_pw
        changed.append('password')

    if new_email is not None:
        new_email = new_email.strip()
        if new_email:
            config['email'] = new_email
            changed.append('email')

    save_config(config)
    return jsonify({'ok': True, 'changed': changed})

@app.route('/api/token', methods=['POST'])
def api_create_token():
    """Create a bearer token. Requires dashboard password."""
    data = request.get_json() or {}
    pw = data.get('password', '')
    if pw != get_dashboard_password():
        return jsonify({'error': 'wrong password'}), 401
    raw = _secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    label = data.get('label', 'api')[:64]
    expires_days = int(data.get('expires_days', 365))
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)).isoformat()
    tokens = load_api_tokens()
    # Remove old token with same label
    tokens = [t for t in tokens if t.get('label') != label]
    tokens.append({'token_hash': token_hash, 'label': label,
                   'created': datetime.datetime.utcnow().isoformat(),
                   'expires_at': expires_at})
    save_api_tokens(tokens)
    return jsonify({'token': raw, 'label': label, 'expires_at': expires_at}), 201

@app.route('/login', methods=['GET', 'POST'])
@csrf_required
def login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if pw == get_dashboard_password():
            session['dashboard_auth'] = True
            session.permanent = True
            return redirect(url_for('dashboard'))
        error = 'Wrong password. Try again.'
    return render_template('login.html', error=error)


@app.route('/forgot-password', methods=['GET', 'POST'])
@csrf_required
def forgot_password():
    sent = False
    if request.method == 'POST':
        import secrets as _sec
        token = _sec.token_urlsafe(32)
        db = sqlite3.connect(_get_reset_db_path())
        # Invalidate old unused tokens
        db.execute('UPDATE pw_resets SET used=1 WHERE used=0')
        db.execute('INSERT INTO pw_resets(token,created_at) VALUES(?,?)',
                   (token, datetime.datetime.utcnow().isoformat()))
        db.commit()
        db.close()
        email_ok = _send_reset_email(token)
        sent = True
    return render_template('forgot_password.html', sent=sent)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@csrf_required
def reset_password(token):
    db   = sqlite3.connect(_get_reset_db_path())
    row  = db.execute('SELECT created_at, used FROM pw_resets WHERE token=?', (token,)).fetchone()
    db.close()

    error   = None
    expired = False

    if not row or row[1]:
        expired = True
    else:
        created = datetime.datetime.fromisoformat(row[0])
        if (datetime.datetime.utcnow() - created).total_seconds() > 1800:  # 30 min
            expired = True

    if expired:
        return render_template('reset_password.html', token=token, expired=True, error=None)

    if request.method == 'POST':
        new_pw  = request.form.get('password', '').strip()
        confirm = request.form.get('confirm', '').strip()
        if len(new_pw) < 6:
            error = 'Password must be at least 6 characters.'
        elif new_pw != confirm:
            error = 'Passwords do not match.'
        else:
            # Save new password
            global config
            config = load_config()
            config['dashboard_password'] = new_pw
            save_config(config)
            # Mark token used
            db2 = sqlite3.connect(_get_reset_db_path())
            db2.execute('UPDATE pw_resets SET used=1 WHERE token=?', (token,))
            db2.commit()
            db2.close()
            return render_template('reset_password.html', token=token, success=True, error=None, expired=False)

    return render_template('reset_password.html', token=token, expired=False, error=error)

@app.route('/logout')
def logout():
    session.pop('dashboard_auth', None)
    return redirect(url_for('index'))

# ── Echo Bridge (EcDash → Echo task queue) ───────────────────────────────────
def load_echo_tasks():
    if os.path.exists(ECHO_TASKS_FILE):
        try:
            with open(ECHO_TASKS_FILE) as f: return json.load(f)
        except: pass
    return []

def save_echo_tasks(tasks):
    with open(ECHO_TASKS_FILE, 'w') as f: json.dump(tasks, f, indent=2)

@app.route('/api/echo-bridge', methods=['POST'])
@login_required
def echo_bridge_send():
    """EcDash sends a task to Echo (OpenClaw). Requires ECHO_WEBHOOK_SECRET."""
    data = request.get_json()
    task_text = data.get('task', '').strip()
    if not task_text:
        return jsonify({'error': 'task required'}), 400
    tasks = load_echo_tasks()
    task = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000),
        'task': task_text,
        'status': 'pending',  # pending / sent / done / failed
        'created': datetime.datetime.utcnow().isoformat(),
        'response': None
    }
    tasks.insert(0, task)
    save_echo_tasks(tasks)

    # Fire to OpenClaw webhook if configured
    echo_webhook = os.environ.get('ECHO_WEBHOOK_URL', '')
    echo_secret  = os.environ.get('ECHO_WEBHOOK_SECRET', '')
    if echo_webhook:
        try:
            payload = json.dumps({
                'task_id': task['id'],
                'task': task_text,
                'from': 'EcDash',
                'secret': echo_secret
            }).encode('utf-8')
            req = urllib.request.Request(
                echo_webhook, data=payload,
                headers={'Content-Type': 'application/json; charset=utf-8'},
                method='POST'
            )
            with _safe_urlopen(req, timeout=10) as r:
                result = json.loads(r.read().decode())
            task['status'] = 'sent'
            task['response'] = result.get('message', 'Task received by Echo')
        except Exception as e:
            task['status'] = 'queued'
            task['response'] = f'Echo offline - task queued. Will process when Echo is available. ({str(e)[:80]})'
    else:
        task['status'] = 'queued'
        task['response'] = '\u2705 Task saved! Echo will pick this up and run it automatically on her next session.'

    tasks[0] = task
    save_echo_tasks(tasks)
    return jsonify(task), 201

@app.route('/api/echo-bridge', methods=['GET'])
@login_required
def echo_bridge_tasks():
    """Get recent Echo tasks and their status."""
    tasks = load_echo_tasks()
    return jsonify(tasks[:20])

@app.route('/api/echo-bridge/<int:task_id>', methods=['PATCH'])
def echo_bridge_update(task_id):
    """Echo calls this to report back task completion. Authenticated by secret."""
    echo_secret = os.environ.get('ECHO_WEBHOOK_SECRET', '')
    incoming = request.headers.get('X-Echo-Secret', '')
    if echo_secret and incoming != echo_secret:
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    tasks = load_echo_tasks()
    for t in tasks:
        if t['id'] == task_id:
            t['status'] = data.get('status', t['status'])
            t['response'] = data.get('response', t['response'])
            t['updated'] = datetime.datetime.utcnow().isoformat()
            save_echo_tasks(tasks)
            return jsonify(t)
    return jsonify({'error': 'not found'}), 404

# ── Notes (Jay ↔ Echo shared notepad) ─────────────────────────────────────────

@app.route('/api/notes', methods=['GET'])
@login_required
def api_notes_get():
    """Get all notes. Optional ?author=jay|echo filter."""
    notes = load_notes()
    author = request.args.get('author')
    if author:
        notes = [n for n in notes if n.get('author','').lower() == author.lower()]
    return jsonify(notes[:100])

@app.route('/api/notes', methods=['POST'])
@login_required
def api_notes_post():
    """Jay writes a note from the dashboard."""
    data = request.get_json()
    text = (data.get('text') or data.get('note') or '').strip()
    if not text:
        return jsonify({'error': 'text required'}), 400
    notes = load_notes()
    note = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000),
        'author': 'jay',
        'text': text,
        'pinned': bool(data.get('pinned', False)),
        'created': datetime.datetime.utcnow().isoformat(),
    }
    notes.insert(0, note)
    save_notes(notes)
    return jsonify(note), 201

@app.route('/api/notes/echo-read', methods=['GET'])
def api_notes_echo_read():
    """Echo fetches Jay's notes (token-authenticated, no session required)."""
    token = request.headers.get('X-Brain-Sync-Token', '')
    if not _check_brain_sync_token(token):
        return jsonify({'error': 'unauthorized'}), 401
    notes = load_notes()
    # Return Jay's notes, pinned first then newest
    jay_notes = [n for n in notes if n.get('author', '') == 'jay']
    jay_notes.sort(key=lambda n: (not n.get('pinned', False), -n.get('id', 0)))
    return jsonify(jay_notes[:50])

@app.route('/api/notes/echo', methods=['POST'])
def api_notes_echo_post():
    """Echo writes a note (token-authenticated, no session required)."""
    token = request.headers.get('X-Brain-Sync-Token', '')
    if not _check_brain_sync_token(token):
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    text = (data.get('text') or data.get('note') or '').strip()
    if not text:
        return jsonify({'error': 'text required'}), 400
    notes = load_notes()
    note = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000),
        'author': 'echo',
        'text': text,
        'pinned': bool(data.get('pinned', False)),
        'created': datetime.datetime.utcnow().isoformat(),
    }
    notes.insert(0, note)
    save_notes(notes)
    return jsonify(note), 201

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def api_notes_delete(note_id):
    notes = load_notes()
    notes = [n for n in notes if n.get('id') != note_id]
    save_notes(notes)
    return jsonify({'ok': True})

@app.route('/api/notes/<int:note_id>/pin', methods=['POST'])
@login_required
def api_notes_pin(note_id):
    notes = load_notes()
    for n in notes:
        if n.get('id') == note_id:
            n['pinned'] = not n.get('pinned', False)
            save_notes(notes)
            return jsonify(n)
    return jsonify({'error': 'not found'}), 404


# ══════════════════════════════════════════════════════════════════════════════
# VAULT — Encrypted Secrets Manager (replaces KYS)
# ══════════════════════════════════════════════════════════════════════════════
import base64, hashlib as _hashlib
from cryptography.fernet import Fernet, InvalidToken

VAULT_DB_PATH = os.path.join(_DATA_DIR, 'vault.db')

def _get_vault_key():
    """Derive a stable Fernet key from the Flask secret key + a salt.
    This means the vault is tied to this instance's secret key — stored on /data."""
    raw = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
    dk  = _hashlib.pbkdf2_hmac('sha256', raw, b'vault-salt-v1', 200_000, dklen=32)
    return base64.urlsafe_b64encode(dk)

def get_vault_db():
    db = sqlite3.connect(VAULT_DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            category    TEXT    NOT NULL DEFAULT 'General',
            label       TEXT    NOT NULL,
            username    TEXT    NOT NULL DEFAULT '',
            secret      TEXT    NOT NULL,          -- Fernet-encrypted value
            url         TEXT    NOT NULL DEFAULT '',
            change_url  TEXT    NOT NULL DEFAULT '',
            notes       TEXT    NOT NULL DEFAULT '',
            created     TEXT    DEFAULT CURRENT_TIMESTAMP,
            updated     TEXT    DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Migrate: add change_url column if it doesn't exist yet
    try:
        db.execute('ALTER TABLE secrets ADD COLUMN change_url TEXT NOT NULL DEFAULT \'\'')
        db.commit()
    except Exception:
        pass  # Column already exists
    db.execute('''
        CREATE TABLE IF NOT EXISTS vault_audit (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            action  TEXT NOT NULL,
            label   TEXT NOT NULL,
            ts      TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.commit()
    return db

def vault_encrypt(plaintext):
    f = Fernet(_get_vault_key())
    return f.encrypt(plaintext.encode()).decode()

def vault_decrypt(ciphertext):
    try:
        f = Fernet(_get_vault_key())
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return '⚠️ Decryption failed'

def vault_audit(action, label):
    try:
        db = get_vault_db()
        db.execute('INSERT INTO vault_audit(action,label) VALUES(?,?)', (action, label))
        db.commit()
        db.close()
    except Exception:
        pass

# ── Vault API routes ──────────────────────────────────────────────────────────

@app.route('/api/vault', methods=['GET'])
@login_required
def vault_list():
    """List all secrets (values redacted)."""
    db = get_vault_db()
    rows = db.execute(
        'SELECT id,category,label,username,url,change_url,notes,created,updated FROM secrets ORDER BY category,label'
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vault', methods=['POST'])
@login_required
def vault_create():
    """Add a new secret."""
    data     = request.get_json()
    label    = (data.get('label') or '').strip()
    secret   = (data.get('secret') or data.get('value') or '').strip()
    if not label or not secret:
        return jsonify({'error': 'label and secret required'}), 400
    encrypted = vault_encrypt(secret)
    db = get_vault_db()
    cur = db.execute(
        '''INSERT INTO secrets(category,label,username,secret,url,change_url,notes)
           VALUES(?,?,?,?,?,?,?)''',
        (
            (data.get('category') or 'General').strip(),
            label,
            (data.get('username') or '').strip(),
            encrypted,
            (data.get('url') or '').strip(),
            (data.get('change_url') or '').strip(),
            (data.get('notes') or '').strip(),
        )
    )
    db.commit()
    row_id = cur.lastrowid
    db.close()
    vault_audit('create', label)
    return jsonify({'ok': True, 'id': row_id}), 201

@app.route('/api/vault/<int:secret_id>', methods=['GET'])
@login_required
def vault_reveal(secret_id):
    """Reveal the decrypted value for a single secret."""
    db = get_vault_db()
    row = db.execute('SELECT * FROM secrets WHERE id=?', (secret_id,)).fetchone()
    db.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    vault_audit('reveal', row['label'])
    return jsonify({**dict(row), 'secret': vault_decrypt(row['secret'])})

@app.route('/api/vault/<int:secret_id>', methods=['PUT'])
@login_required
def vault_update(secret_id):
    """Update an existing secret."""
    data = request.get_json()
    db   = get_vault_db()
    row  = db.execute('SELECT * FROM secrets WHERE id=?', (secret_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'not found'}), 404
    new_secret = (data.get('secret') or data.get('value') or '').strip()
    encrypted  = vault_encrypt(new_secret) if new_secret else row['secret']
    db.execute('''
        UPDATE secrets SET
            category=?, label=?, username=?, secret=?, url=?, change_url=?, notes=?,
            updated=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (
        (data.get('category')   or row['category']).strip(),
        (data.get('label')      or row['label']).strip(),
        (data.get('username')   or row['username'] or '').strip(),
        encrypted,
        (data.get('url')        or row['url'] or '').strip(),
        (data.get('change_url') if 'change_url' in data else (row['change_url'] if 'change_url' in dict(row) else '')),
        (data.get('notes')      or row['notes'] or '').strip(),
        secret_id,
    ))
    db.commit()
    db.close()
    vault_audit('update', data.get('label') or row['label'])
    return jsonify({'ok': True})

@app.route('/api/vault/<int:secret_id>', methods=['DELETE'])
@login_required
def vault_delete(secret_id):
    """Delete a secret."""
    db  = get_vault_db()
    row = db.execute('SELECT label FROM secrets WHERE id=?', (secret_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'not found'}), 404
    label = row['label']
    db.execute('DELETE FROM secrets WHERE id=?', (secret_id,))
    db.commit()
    db.close()
    vault_audit('delete', label)
    return jsonify({'ok': True})

@app.route('/api/vault/categories', methods=['GET'])
@login_required
def vault_categories():
    db = get_vault_db()
    rows = db.execute('SELECT DISTINCT category FROM secrets ORDER BY category').fetchall()
    db.close()
    return jsonify([r['category'] for r in rows])

@app.route('/api/vault/echo', methods=['GET'])
def vault_echo_read():
    """Echo reads specific secrets by label (token-auth, no session)."""
    token      = request.headers.get('X-Brain-Sync-Token', '')
    if not _check_brain_sync_token(token):
        return jsonify({'error': 'unauthorized'}), 401
    labels = request.args.getlist('label')
    if not labels:
        return jsonify({'error': 'label param required'}), 400
    db   = get_vault_db()
    out  = {}
    for lbl in labels:
        row = db.execute('SELECT * FROM secrets WHERE label=?', (lbl,)).fetchone()
        if row:
            out[lbl] = vault_decrypt(row['secret'])
            vault_audit('echo-read', lbl)
    db.close()
    return jsonify(out)


# ── Phase 2: App-to-EcDash key pull ──────────────────────────────────────────
# Each Liberty-Emporium app can register an app token and pull its own secrets.
# Apps hit POST /api/vault/app-keys with {"app": "FloodClaim Pro", "token": "...", "labels": [...]}

def _get_app_token_db():
    db = get_vault_db()  # reuse same DB
    db.execute('''
        CREATE TABLE IF NOT EXISTS app_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name    TEXT NOT NULL UNIQUE,
            token_hash  TEXT NOT NULL,
            categories  TEXT DEFAULT '',
            created     TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.commit()
    return db

@app.route('/api/vault/app-keys', methods=['POST'])
def vault_app_keys():
    """Phase 2: Liberty-Emporium apps pull their own secrets at startup.
    
    POST body: {"app": "FloodClaim Pro", "token": "<app-token>", "labels": ["Stripe Secret Key", ...]}
    Returns: {"Stripe Secret Key": "sk_live_..."}
    """
    import hashlib as _hl
    data       = request.get_json(silent=True) or {}
    app_name   = (data.get('app') or '').strip()
    raw_token  = (data.get('token') or '').strip()
    labels     = data.get('labels', [])
    if not app_name or not raw_token:
        return jsonify({'error': 'app and token required'}), 400
    token_hash = _hl.sha256(raw_token.encode()).hexdigest()
    db = _get_app_token_db()
    row = db.execute('SELECT * FROM app_tokens WHERE app_name=?', (app_name,)).fetchone()
    if not row or row['token_hash'] != token_hash:
        db.close()
        return jsonify({'error': 'unauthorized'}), 401
    allowed_cats = set(c.strip() for c in (row['categories'] or '').split(',') if c.strip())
    out = {}
    for lbl in labels:
        secret_row = db.execute('SELECT * FROM secrets WHERE label=?', (lbl,)).fetchone()
        if secret_row:
            # Only return if no category restriction, or category is allowed
            if not allowed_cats or secret_row['category'] in allowed_cats:
                out[lbl] = vault_decrypt(secret_row['secret'])
                vault_audit(f'app-pull:{app_name}', lbl)
    db.close()
    return jsonify(out)

@app.route('/api/vault/app-tokens', methods=['GET'])
@login_required
def vault_app_tokens_list():
    """List registered app tokens (admin)."""
    db = _get_app_token_db()
    rows = db.execute('SELECT id, app_name, categories, created FROM app_tokens ORDER BY app_name').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vault/app-tokens', methods=['POST'])
@login_required
def vault_app_tokens_create():
    """Register an app token."""
    import hashlib as _hl, secrets as _sec
    data       = request.get_json(silent=True) or {}
    app_name   = (data.get('app_name') or '').strip()
    categories = (data.get('categories') or '').strip()
    if not app_name:
        return jsonify({'error': 'app_name required'}), 400
    raw_token  = _sec.token_urlsafe(40)
    token_hash = _hl.sha256(raw_token.encode()).hexdigest()
    db = _get_app_token_db()
    db.execute('INSERT OR REPLACE INTO app_tokens(app_name,token_hash,categories) VALUES(?,?,?)',
               (app_name, token_hash, categories))
    db.commit()
    db.close()
    vault_audit('app-token-created', app_name)
    return jsonify({'app_name': app_name, 'token': raw_token,
                    'note': 'Save this token — it will not be shown again. Set as ECDASH_APP_TOKEN in Railway.'})

@app.route('/api/vault/app-tokens/<int:token_id>', methods=['DELETE'])
@login_required
def vault_app_tokens_delete(token_id):
    """Revoke an app token."""
    db = _get_app_token_db()
    db.execute('DELETE FROM app_tokens WHERE id=?', (token_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True})


@app.route('/api/admin/reset-brain-token', methods=['POST', 'GET'])
def api_reset_brain_token():
    """Delete stale brain_sync_token.txt so env var takes effect on next request.
    Accepts session login OR ?pw=DASHBOARD_PASSWORD query param."""
    import os as _os
    # No auth — one-time migration tool, token value is not exposed
    deleted = False
    file_token_before = ''
    env_token = os.environ.get('BRAIN_SYNC_TOKEN', '')
    if _os.path.exists(_BRAIN_SYNC_TOKEN_FILE):
        file_token_before = open(_BRAIN_SYNC_TOKEN_FILE).read().strip()
        _os.remove(_BRAIN_SYNC_TOKEN_FILE)
        deleted = True
    _register_brain_sync_token()
    file_token_after = ''
    if _os.path.exists(_BRAIN_SYNC_TOKEN_FILE):
        file_token_after = open(_BRAIN_SYNC_TOKEN_FILE).read().strip()
    return jsonify({
        'ok': True,
        'deleted': deleted,
        'env_set': bool(env_token),
        'file_before_hash': __import__('hashlib').sha256(file_token_before.encode()).hexdigest()[:12] if file_token_before else None,
        'file_after_hash': __import__('hashlib').sha256(file_token_after.encode()).hexdigest()[:12] if file_token_after else None,
    })


@app.route('/api/settings', methods=['GET'])
@login_required
def api_settings_get():
    return jsonify(load_app_settings())

@app.route('/api/settings', methods=['POST'])
@login_required
def api_settings_save():
    data = request.get_json()
    s = load_app_settings()
    allowed = {'echo_model', 'echo_max_tokens', 'echo_temperature',
                'echo_agent_name', 'echo_agent_tagline', 'echo_system_prompt'}
    for k, v in data.items():
        if k in allowed: s[k] = v
    save_app_settings(s)
    return jsonify({'ok': True, 'settings': s})

# ── App health checker ────────────────────────────────────────────────────────
APPS_REGISTRY = [
    {'name': 'Liberty Inventory',     'url': 'https://liberty-emporium-and-thrift-inventory-app-production.up.railway.app'},
    {'name': 'Inventory Demo',        'url': 'https://liberty-emporium-inventory-demo-app-production.up.railway.app'},
    {'name': 'Pet Vet AI',            'url': 'https://pet-vet-ai-production.up.railway.app'},
    {'name': 'GymForge',              'url': 'https://web-production-1c23.up.railway.app'},
    {'name': 'Contractor Pro AI',     'url': 'https://contractor.ai.solutions.alexanderai.site'},
    {'name': 'Consignment Solutions', 'url': 'https://consignment.ai.solutions.alexanderai.site'},
    {'name': 'FloodClaim Pro',         'url': 'https://billy-floods.up.railway.app'},
    {'name': 'Liberty Oil & Propane',  'url': 'https://liberty-oil-propane.up.railway.app'},
    {'name': 'Alexander AI Voice',      'url': 'https://voice.alexanderai.site'},
    {'name': 'AI Agent Widget',         'url': 'https://ai.widget.alexanderai.site'},
    {'name': 'Drop Shipping',           'url': 'https://shop.alexanderai.site'},
    {'name': 'List It Everywhere',      'url': 'https://web-production-c799c.up.railway.app'},
    {'name': 'AI Info Site',             'url': 'https://ai.info1.alexanderai.site'},
]

def ping_app(app_entry, results):
    url = app_entry['url']
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'EchoHealthCheck/1.0'})
        with _safe_urlopen(req, timeout=8) as r:
            ms = int((time.time() - start) * 1000)
            results.append({'name': app_entry['name'], 'url': url, 'status': r.status, 'ms': ms, 'ok': r.status < 400})
    except urllib.error.HTTPError as e:
        ms = int((time.time() - start) * 1000)
        results.append({'name': app_entry['name'], 'url': url, 'status': e.code, 'ms': ms, 'ok': e.code < 400})
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        results.append({'name': app_entry['name'], 'url': url, 'status': 0, 'ms': ms, 'ok': False, 'error': str(e)[:60]})

def check_all_apps():
    results = []
    threads = [threading.Thread(target=ping_app, args=(a, results)) for a in APPS_REGISTRY]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    name_order = {a['name']: i for i, a in enumerate(APPS_REGISTRY)}
    results.sort(key=lambda x: name_order.get(x['name'], 99))
    return results

@app.route('/api/network-scan', methods=['GET'])
@login_required
def api_network_scan():
    """Server-side network scan — pings all Liberty-Emporium apps and returns status.
    Runs on the server so there are no browser CORS issues.
    """
    import threading as _th, time as _t
    APP_URLS = {
        'EcDash':             'https://jay-portfolio-production.up.railway.app',
        'FloodClaim Pro':     'https://billy-floods.up.railway.app',
        'AI Agent Widget':    'https://ai.widget.alexanderai.site',
        'Sweet Spot Cakes':   'https://sweet-spot-cakes.up.railway.app',
        'Pet Vet AI':         'https://pet-vet-ai-production.up.railway.app',
        'Contractor Pro AI':  'https://contractor-pro-ai-production.up.railway.app',
        'Drop Shipping':      'https://shop.alexanderai.site',
        'Consignment':        'https://web-production-43ce4.up.railway.app',
        'Liberty Inventory':  'https://liberty-emporium-inventory-demo-app-production.up.railway.app',
        'GymForge':           'https://web-production-1c23.up.railway.app',
        'Liberty Oil':        'https://liberty-oil-propane.up.railway.app',
        "Grace (Mom's AI)":   'https://moms-ai-helper.up.railway.app',
    }
    results = {}
    lock = _th.Lock()

    def _ping(name, base_url):
        start = _t.time()
        for path in ['/api/status', '/health']:
            try:
                import urllib.request as _ur
                req = _ur.Request(base_url + path, method='GET')
                with _ur.urlopen(req, timeout=6) as r:
                    ms = int((_t.time() - start) * 1000)
                    try: body = json.loads(r.read().decode())
                    except: body = {}
                    with lock:
                        results[name] = {
                            'healthy':       True,
                            'ms':            ms,
                            'uptime_human':  body.get('uptime_human', ''),
                            'stats':         body.get('stats', {}),
                            'url':           base_url,
                        }
                    return
            except Exception:
                pass
        with lock:
            results[name] = {'healthy': False, 'ms': int((_t.time()-start)*1000), 'url': base_url}

    threads = [_th.Thread(target=_ping, args=(n, u), daemon=True) for n, u in APP_URLS.items()]
    for t in threads: t.start()
    for t in threads: t.join(timeout=12)

    healthy = sum(1 for v in results.values() if v.get('healthy'))
    return jsonify({
        'apps_healthy': healthy,
        'apps_total':   len(APP_URLS),
        'results':      results,
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Public health endpoint — used by self-check and Railway health probes."""
    db_status = 'ok'
    try:
        import sqlite3 as _s3
        conn = _s3.connect(CHAT_DB_PATH)
        conn.execute('SELECT 1')
        conn.close()
    except Exception:
        db_status = 'error'
    return jsonify({'status': 'ok', 'db': db_status})

@app.route('/api/sweet-spot-users')
@login_required
def api_sweet_spot_users():
    """Proxy to Sweet Spot Cakely API — returns app login users with passwords."""
    SWEET_SPOT_URL = 'https://sweet-spot-cakes.up.railway.app/cakely/api/users'
    CAKELY_TOKEN   = os.environ.get('CAKELY_API_TOKEN', 'cakely-sweet-spot-2026')
    try:
        req = urllib.request.Request(
            SWEET_SPOT_URL,
            headers={'Authorization': f'Bearer {CAKELY_TOKEN}'}
        )
        with _safe_urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({'ok': False, 'users': [], 'error': str(e)}), 200


@app.route('/api/sweet-spot-employees')
@login_required
def api_sweet_spot_employees():
    """Proxy to Sweet Spot Cakely API — returns employee list with PINs."""
    SWEET_SPOT_URL = 'https://sweet-spot-cakes.up.railway.app/cakely/api/employees'
    CAKELY_TOKEN   = os.environ.get('CAKELY_API_TOKEN', 'cakely-sweet-spot-2026')
    try:
        req = urllib.request.Request(
            SWEET_SPOT_URL,
            headers={'Authorization': f'Bearer {CAKELY_TOKEN}'}
        )
        with _safe_urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({'ok': False, 'employees': [], 'error': str(e)}), 200


@app.route('/api/health', methods=['GET'])
@login_required
def api_health():
    results = check_all_apps()
    up = sum(1 for r in results if r['ok'])
    return jsonify({'results': results, 'up': up, 'total': len(results),
                    'checked_at': datetime.datetime.utcnow().isoformat()})

# ── Echo brain (loads from /data volume or bundled data/) ────────────────────
DATA_DIR = os.environ.get('ECHO_DATA_DIR',
    os.path.join(os.path.dirname(__file__), 'data'))

def load_brain_file(filename):
    """Load a brain file from the data volume. Returns empty string if missing."""
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f: return f.read()
        except: pass
    return ''

def save_brain_file(filename, content):
    """Save a brain file to the data volume."""
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f: f.write(content)

def get_app_file_tree():
    """Return a compact file tree of the app for EcDash's context."""
    import shutil
    lines = []
    for d in ['templates', 'static']:
        dir_path = os.path.join(APP_ROOT, d)
        if not os.path.isdir(dir_path): continue
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1]
                if ext in _CODE_ALLOWED_EXTS:
                    rel = os.path.relpath(os.path.join(root, fname), APP_ROOT)
                    size = os.path.getsize(os.path.join(root, fname))
                    lines.append(f'  {rel} ({size//1024}kb)' if size > 1024 else f'  {rel} ({size}b)')
    return '\n'.join(lines)

def build_system_prompt(coding_mode=False):
    """Build Echo's system prompt from brain files. Falls back to defaults."""
    soul     = load_brain_file('SOUL.md')
    identity = load_brain_file('IDENTITY.md')
    memory   = load_brain_file('MEMORY.md')
    s        = load_app_settings()
    agent_name = s.get('echo_agent_name', 'EcDash')

    base = f"""You are {agent_name} — the AI for Jay Alexander's Command Center at alexanderai.site (Liberty-Emporium / Alexander AI Integrated Solutions).
Never say you are ChatGPT, Claude, Gemini, or any other AI product. You are {agent_name}."""

    parts = [base]
    if identity: parts.append('\n---\n# YOUR IDENTITY\n' + identity)
    if soul:     parts.append('\n---\n# YOUR SOUL & PERSONALITY\n' + soul)
    if memory:   parts.append('\n---\n# YOUR MEMORY (read this carefully)\n' + memory)
    parts.append('\n---\nBe concise, direct, warm. You have opinions. Say "we" about Jay\'s projects. Skip filler like "Great question!".')

    if coding_mode:
        file_tree = get_app_file_tree()
        parts.append(f"""
---
# YOUR CODING CAPABILITIES

You are a skilled developer. You can read and write files in this dashboard app.
The app is built with Python/Flask, Jinja2 templates, vanilla JS, Bootstrap 5.

## App File Tree
{file_tree}

## How to Write Files
When Jay asks you to make a change to the dashboard, you MUST:
1. Think through what needs to change
2. Write the complete updated file using the WRITE_FILE block syntax below
3. Briefly explain what you changed and why

## WRITE_FILE Syntax
To write a file, include a block like this in your response:

<<<WRITE_FILE: templates/dashboard.html>>>
[complete file content here]
<<<END_FILE>>>

Rules:
- Always write the COMPLETE file — never partial snippets with "rest stays the same"
- You can write multiple files in one response
- Only templates/ and static/ files are allowed
- A .bak backup is automatically created before every write
- After writing, tell Jay what you changed and what to look for
- If Jay says "undo" or "revert", you can restore from the .bak file

## Coding Standards (non-negotiable)
- All password fields: show/hide eye toggle (👁️/🙈)
- CSRF tokens on all forms
- Security headers on all routes
- No debug=True in production
- /health endpoint on every app
- bcrypt for passwords, never MD5/SHA1
- Push all changes to GitHub after saving
- Bootstrap 5 for UI, consistent dark theme

## Current Design System
```css
--bg:#030712; --bg2:#0a0f1a; --card:#111827;
--border:#1f2937; --accent:#6366f1; --accent3:#a78bfa;
--green:#10b981; --yellow:#f59e0b; --red:#ef4444;
--grad: linear-gradient(135deg,#6366f1,#8b5cf6,#a78bfa);
```
""")

    return '\n'.join(parts)

# Brain file API routes
@app.route('/api/brain/<filename>', methods=['GET'])
@login_required
def brain_get(filename):
    allowed = {'SOUL.md', 'IDENTITY.md', 'MEMORY.md'}
    if filename not in allowed:
        return jsonify({'error': 'not allowed'}), 403
    return jsonify({'filename': filename, 'content': load_brain_file(filename)})

@app.route('/api/brain/<filename>', methods=['POST'])
@login_required
def brain_save(filename):
    allowed = {'SOUL.md', 'IDENTITY.md', 'MEMORY.md'}
    if filename not in allowed:
        return jsonify({'error': 'not allowed'}), 403
    data = request.get_json()
    content = data.get('content', '')
    save_brain_file(filename, content)
    return jsonify({'ok': True, 'filename': filename})

# ── Echo chat ─────────────────────────────────────────────────────────────────


@app.route('/api/brain/sync', methods=['POST'])
def brain_sync():
    """Receive brain push from AI Agent Widget. Token-protected, no session required."""
    auth = request.headers.get('X-Brain-Sync-Token', '')
    if not _check_brain_sync_token(auth):
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    allowed = {'IDENTITY.md', 'SOUL.md', 'MEMORY.md'}
    saved = []
    for filename, content in data.items():
        if filename in allowed:
            save_brain_file(filename, content or '')
            saved.append(filename)
    return jsonify({'ok': True, 'synced': saved})

@app.route('/chat')
def chat():
    # Allow access via session cookie OR permanent bearer token in query param
    # Bearer token in URL: /chat?token=<CHAT_BEARER_TOKEN>
    # This avoids the session-expiry problem after redeploys.
    import hashlib as _hl
    if not session.get('dashboard_auth'):
        # Check query param token
        qt = request.args.get('token', '')
        env_token = os.environ.get('CHAT_BEARER_TOKEN', '')
        if not (qt and env_token and qt == env_token):
            # Check Authorization header as fallback
            if not check_bearer_token():
                return redirect(url_for('login'))
    chat_token = os.environ.get('CHAT_BEARER_TOKEN', '')
    return render_template('chat.html', config=config, chat_token=chat_token)

_CODE_KEYWORDS = [
    'change', 'update', 'edit', 'fix', 'add', 'remove', 'delete', 'rename',
    'redesign', 'rebuild', 'refactor', 'make', 'create', 'build', 'write',
    'color', 'style', 'css', 'html', 'button', 'page', 'layout', 'sidebar',
    'nav', 'header', 'footer', 'font', 'dashboard', 'template', 'code'
]

def _execute_write_files(reply_text):
    """Parse and execute WRITE_FILE blocks from EcDash's reply. Returns list of saved paths."""
    import re, shutil
    saved = []
    pattern = r'<<<WRITE_FILE:\s*([^>\n]+)>>>\n?([\s\S]*?)<<<END_FILE>>>'
    for match in re.finditer(pattern, reply_text):
        rel_path = match.group(1).strip()
        content  = match.group(2)
        full = _safe_code_path(rel_path)
        if not full:
            app.logger.warning(f'EcDash tried to write disallowed path: {rel_path}')
            continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.exists(full):
            shutil.copy2(full, full + '.bak')
        with open(full, 'w', encoding='utf-8') as f:
            f.write(content)
        app.logger.info(f'EcDash wrote: {rel_path} ({len(content)} chars)')
        saved.append(rel_path)
    return saved

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.get_json()
    user_message = data.get('message', '').strip()
    history = data.get('history', [])
    if not user_message:
        return jsonify({'error': 'message required'}), 400

    openrouter_key = os.environ.get('OPENROUTER_API_KEY', '')
    if not openrouter_key:
        return jsonify({'reply': 'OpenRouter API key not configured. Add OPENROUTER_API_KEY to Railway environment variables.'})

    # Detect if this is a coding request
    msg_lower = user_message.lower()
    is_coding = any(kw in msg_lower for kw in _CODE_KEYWORDS)
    system_content = build_system_prompt(coding_mode=is_coding)

    # Inject live health data if relevant
    health_keywords = ['health', 'status', 'up', 'down', 'live', 'working', 'test', 'ping', 'check', 'running', 'broken', 'crash', 'offline']
    if any(kw in msg_lower for kw in health_keywords):
        try:
            health = check_all_apps()
            lines = ['\n\nLIVE APP HEALTH (checked right now):']
            for r in health:
                icon = 'UP' if r['ok'] else 'DOWN'
                lines.append(f"- {r['name']}: {icon} (HTTP {r['status']}, {r['ms']}ms)")
            up = sum(1 for r in health if r['ok'])
            lines.append(f"\nSummary: {up}/{len(health)} apps are up.")
            system_content += '\n'.join(lines)
        except Exception:
            pass

    messages = [{'role': 'system', 'content': system_content}]
    for h in history[-10:]:
        if h.get('role') in ('user', 'assistant'):
            messages.append({'role': h['role'], 'content': h['content']})
    messages.append({'role': 'user', 'content': user_message})

    s = load_app_settings()
    # Use a stronger model for coding tasks
    model = s['echo_model']
    if is_coding and model in ('meta-llama/llama-3.1-70b-instruct', 'google/gemini-flash-1.5'):
        model = 'anthropic/claude-3.5-haiku'  # upgrade weak models for code

    payload = json.dumps({
        'model': model,
        'messages': messages,
        'max_tokens': 4096 if is_coding else s['echo_max_tokens'],
        'temperature': 0.3 if is_coding else s['echo_temperature']
    }).encode('utf-8')
    req = urllib.request.Request(
        'https://openrouter.ai/api/v1/chat/completions', data=payload,
        headers={'Authorization': f'Bearer {openrouter_key}',
                 'Content-Type': 'application/json; charset=utf-8',
                 'HTTP-Referer': 'https://alexanderai.site',
                 'X-Title': 'EcDash - Jay Alexander Command Center'})
    try:
        with _safe_urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            reply = result['choices'][0]['message']['content']
            # Execute any WRITE_FILE blocks
            files_written = _execute_write_files(reply) if is_coding else []
            # Strip the raw WRITE_FILE blocks from the visible reply
            import re
            clean_reply = re.sub(
                r'<<<WRITE_FILE:[^>\n]+>>>\n?[\s\S]*?<<<END_FILE>>>\n?',
                '', reply
            ).strip()
            return jsonify({
                'reply': clean_reply,
                'files_written': files_written,
                'coding_mode': is_coding
            })
    except Exception as e:
        return jsonify({'reply': f'EcDash is unavailable right now. Error: {str(e)[:100]}'})


# ── Chat history API ──────────────────────────────────────────────────────────

@app.route('/api/conversations', methods=['GET'])
@login_required
def api_conversations_list():
    db = get_chat_db()
    rows = db.execute(
        'SELECT id, title, created, updated FROM conversations ORDER BY updated DESC LIMIT 100'
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/conversations', methods=['POST'])
@login_required
def api_conversations_new():
    db = get_chat_db()
    cur = db.execute("INSERT INTO conversations (title) VALUES ('New Conversation')")
    db.commit()
    conv_id = cur.lastrowid
    db.close()
    return jsonify({'id': conv_id, 'title': 'New Conversation'})

@app.route('/api/conversations/<int:conv_id>', methods=['GET'])
@login_required
def api_conversation_get(conv_id):
    db = get_chat_db()
    conv = db.execute('SELECT * FROM conversations WHERE id=?', (conv_id,)).fetchone()
    if not conv:
        db.close()
        return jsonify({'error': 'not found'}), 404
    msgs = db.execute(
        'SELECT role, content, created FROM messages WHERE conversation_id=? ORDER BY id',
        (conv_id,)).fetchall()
    db.close()
    return jsonify({'conversation': dict(conv), 'messages': [dict(m) for m in msgs]})

@app.route('/api/conversations/<int:conv_id>', methods=['DELETE'])
@login_required
def api_conversation_delete(conv_id):
    db = get_chat_db()
    db.execute('DELETE FROM messages WHERE conversation_id=?', (conv_id,))
    db.execute('DELETE FROM conversations WHERE id=?', (conv_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True})

@app.route('/api/conversations/<int:conv_id>/messages', methods=['POST'])
@login_required
def api_conversation_add_message(conv_id):
    data    = request.get_json()
    role    = data.get('role', 'user')
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'content required'}), 400
    db = get_chat_db()
    conv = db.execute('SELECT * FROM conversations WHERE id=?', (conv_id,)).fetchone()
    if not conv:
        db.close()
        return jsonify({'error': 'not found'}), 404
    db.execute('INSERT INTO messages (conversation_id, role, content) VALUES (?,?,?)',
               (conv_id, role, content))
    if role == 'user' and conv['title'] == 'New Conversation':
        title = content.strip()[:60] + ('...' if len(content) > 60 else '')
        db.execute('UPDATE conversations SET title=?, updated=CURRENT_TIMESTAMP WHERE id=?',
                   (title, conv_id))
    else:
        db.execute('UPDATE conversations SET updated=CURRENT_TIMESTAMP WHERE id=?', (conv_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True})

# ── Todos API ─────────────────────────────────────────────────────────────────
@app.route('/api/todos', methods=['GET'])
@login_required
def api_todos_get():
    return jsonify(load_todos())

@app.route('/api/todos', methods=['POST'])
@login_required
def api_todos_add():
    data = request.get_json()
    todos = load_todos()
    todo = {'id': int(datetime.datetime.utcnow().timestamp() * 1000),
            'text': data.get('text', '').strip(), 'priority': data.get('priority', 'medium'),
            'done': False, 'created': datetime.datetime.utcnow().isoformat()}
    if not todo['text']:
        return jsonify({'error': 'text required'}), 400
    todos.insert(0, todo)
    save_todos(todos)
    return jsonify(todo), 201

@app.route('/api/todos/<int:todo_id>', methods=['PATCH'])
@login_required
def api_todos_update(todo_id):
    data = request.get_json()
    todos = load_todos()
    for t in todos:
        if t['id'] == todo_id:
            if 'done' in data: t['done'] = data['done']
            if 'text' in data: t['text'] = data['text']
            if 'priority' in data: t['priority'] = data['priority']
            t['updated'] = datetime.datetime.utcnow().isoformat()
            save_todos(todos)
            return jsonify(t)
    return jsonify({'error': 'not found'}), 404

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@login_required
def api_todos_delete(todo_id):
    todos = [t for t in load_todos() if t['id'] != todo_id]
    save_todos(todos)
    return jsonify({'ok': True})

# ── Tickets ───────────────────────────────────────────────────────────────
@app.route('/tickets')
@login_required
def tickets():
    return render_template('tickets.html', config=config)

@app.route('/api/tickets', methods=['GET'])
@login_required
def api_tickets_get():
    return jsonify(load_tickets())

@app.route('/api/tickets', methods=['POST'])
@login_required
def api_tickets_add():
    data = request.get_json()
    tickets = load_tickets()
    ticket = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000) % 100000,
        'app': data.get('app', 'Unknown').strip(),
        'subject': data.get('subject', '').strip(),
        'message': data.get('message', '').strip(),
        'name': data.get('name', '').strip(),
        'email': data.get('email', '').strip(),
        'priority': data.get('priority', 'normal'),
        'status': 'open',
        'created': datetime.datetime.utcnow().isoformat(),
        'updated': datetime.datetime.utcnow().isoformat()
    }
    if not ticket['subject'] or not ticket['message']:
        return jsonify({'error': 'subject and message required'}), 400
    tickets.insert(0, ticket)
    save_tickets(tickets)
    return jsonify(ticket), 201

@app.route('/api/tickets/<int:ticket_id>', methods=['PATCH'])
@login_required
def api_tickets_update(ticket_id):
    data = request.get_json()
    tickets = load_tickets()
    for t in tickets:
        if t['id'] == ticket_id:
            if 'status' in data: t['status'] = data['status']
            if 'priority' in data: t['priority'] = data['priority']
            t['updated'] = datetime.datetime.utcnow().isoformat()
            save_tickets(tickets)
            return jsonify(t)
    return jsonify({'error': 'not found'}), 404

# Public ticket submission (no login required — for embedding in other apps)
@app.route('/submit-ticket', methods=['GET', 'POST'])
@csrf_required
def submit_ticket():
    app_name = request.args.get('app', request.form.get('app', 'Unknown'))
    if request.method == 'POST':
        tickets = load_tickets()
        ticket = {
            'id': int(datetime.datetime.utcnow().timestamp() * 1000) % 100000,
            'app': request.form.get('app', app_name).strip(),
            'subject': request.form.get('subject', '').strip(),
            'message': request.form.get('message', '').strip(),
            'name': request.form.get('name', '').strip(),
            'email': request.form.get('email', '').strip(),
            'priority': 'normal',
            'status': 'open',
            'created': datetime.datetime.utcnow().isoformat(),
            'updated': datetime.datetime.utcnow().isoformat()
        }
        if ticket['subject'] and ticket['message']:
            tickets.insert(0, ticket)
            save_tickets(tickets)
        return render_template('submit_ticket_success.html', app_name=ticket['app'])
    return render_template('submit_ticket.html', app_name=app_name)

# ── Public routes ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html', config=config)

@app.route('/court/qr')
def court_qr():
    return render_template('court_qr.html')

@app.route('/flyer')
def flyer():
    return render_template('flyer.html')

@app.route('/court')
def court():
    return render_template('court.html')

# ── Bot / scanner sink ───────────────────────────────────────────────────────
# Returns 410 Gone for every path that scanners probe but will never exist.
# Keeps these out of the real error-monitor table.
_BOT_PATHS = [
    '/wp-admin/', '/wp-login.php', '/wp-cron.php', '/wp-includes/',
    '/wp-content/', '/xmlrpc.php', '/wp-admin/install.php',
    '/wp-json/', '/.env', '/.git/', '/config.php', '/setup.php',
    '/install.php', '/phpmyadmin/', '/pma/', '/admin/config.php',
    '/sitemap.xml', '/sitemap_index.xml', '/robots.txt.bak',
    '/.htaccess', '/web.config', '/backup/', '/administrator/',
    '/joomla/', '/drupal/', '/typo3/',
]

@app.before_request
def block_bot_paths():
    from flask import request as _req
    path = _req.path
    if any(path == p or path.startswith(p) for p in _BOT_PATHS):
        return '', 410  # 410 Gone — tells scanners to stop retrying

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'not found'}), 404
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/robots.txt')
def robots():
    return app.response_class(
        "User-agent: *\nAllow: /\nAllow: /apps\nDisallow: /tools\nDisallow: /admin\nDisallow: /court\nDisallow: /flyer\n",
        mimetype="text/plain")

@app.route('/apps')
def apps():
    return render_template('apps.html')

@app.route('/investors')
def investors():
    return render_template('investors.html', config=config)

@app.route('/investor-inquiry', methods=['POST'])
@csrf_required
def investor_inquiry():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    interest = request.form.get('interest', '')
    message = request.form.get('message', '').strip()
    log_path = os.path.join(os.path.dirname(__file__), 'investor_inquiries.log')
    with open(log_path, 'a') as f:
        f.write(f"\n{'='*60}\nDate: {datetime.datetime.now()}\nName: {name}\nEmail: {email}\nInterest: {interest}\nMessage: {message}\n")
    flash(f'Thanks {name}! Jay will get back to you at {email} within 24 hours.', 'success')
    return redirect(url_for('investors') + '#contact')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/dashboard')
@login_required
def dashboard():
    chat_token = os.environ.get('CHAT_BEARER_TOKEN', '')
    return render_template('dashboard.html', config=config, chat_token=chat_token)

# ── Code Editor ──────────────────────────────────────────────────────────────
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
_CODE_ALLOWED_DIRS = ['templates', 'static']
_CODE_ALLOWED_EXTS = {'.html', '.css', '.js', '.json', '.txt', '.md', '.py'}

def _safe_code_path(rel_path):
    """Resolve a relative path and ensure it stays inside APP_ROOT."""
    full = os.path.normpath(os.path.join(APP_ROOT, rel_path))
    if not full.startswith(APP_ROOT + os.sep) and full != APP_ROOT:
        return None
    top = rel_path.split(os.sep)[0] if rel_path else ''
    if top not in _CODE_ALLOWED_DIRS:
        return None
    _, ext = os.path.splitext(full)
    if ext not in _CODE_ALLOWED_EXTS:
        return None
    return full

@app.route('/code')
@login_required
def code_editor():
    """EcDash code editor — browse and edit templates & static files."""
    return render_template('code.html', config=config)

@app.route('/api/code/files')
@login_required
def api_code_files():
    """Return the file tree for allowed directories."""
    tree = []
    for d in _CODE_ALLOWED_DIRS:
        dir_path = os.path.join(APP_ROOT, d)
        if not os.path.isdir(dir_path):
            continue
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [x for x in sorted(dirs) if not x.startswith('.')]
            for fname in sorted(files):
                _, ext = os.path.splitext(fname)
                if ext not in _CODE_ALLOWED_EXTS:
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, APP_ROOT)
                size = os.path.getsize(full)
                tree.append({'path': rel, 'size': size})
    return jsonify(tree)

@app.route('/api/code/file', methods=['GET'])
@login_required
def api_code_file_get():
    """Read a file."""
    rel = request.args.get('path', '')
    full = _safe_code_path(rel)
    if not full or not os.path.isfile(full):
        return jsonify({'error': 'not found or not allowed'}), 404
    with open(full, encoding='utf-8', errors='replace') as f:
        content = f.read()
    return jsonify({'path': rel, 'content': content})

@app.route('/api/code/file', methods=['POST'])
@login_required
def api_code_file_save():
    """Save a file. Creates a .bak backup first."""
    data = request.get_json(silent=True) or {}
    rel = data.get('path', '')
    content = data.get('content', '')
    full = _safe_code_path(rel)
    if not full:
        return jsonify({'error': 'not allowed'}), 403
    os.makedirs(os.path.dirname(full), exist_ok=True)
    # Backup
    if os.path.exists(full):
        import shutil
        shutil.copy2(full, full + '.bak')
    with open(full, 'w', encoding='utf-8') as f:
        f.write(content)
    app.logger.info(f'Code editor saved: {rel}')
    return jsonify({'ok': True, 'path': rel, 'bytes': len(content.encode())})

# ─────────────────────────────────────────────────────────────────────────────

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@csrf_required
def settings():
    global config
    if request.method == 'POST':
        config['name'] = request.form.get('name', '').strip()
        config['tagline'] = request.form.get('tagline', '').strip()
        config['email'] = request.form.get('email', '').strip()
        config['photo_url'] = request.form.get('photo_url', '').strip()
        config['photo'] = request.form.get('photo', '👨‍💻').strip()
        save_config(config)
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', config=config)

@app.route('/admin', methods=['GET', 'POST'])
@csrf_required
def admin():
    global config
    if request.method == 'POST':
        config['photo'] = request.form.get('photo', '👨‍💻')
        config['name'] = request.form.get('name', '')
        config['tagline'] = request.form.get('tagline', '')
        config['email'] = request.form.get('email', '')
        config['photo_url'] = request.form.get('photo_url', '')
        save_config(config)
        flash('Changes saved!', 'success')
    return render_template('admin.html', config=config)

@app.route('/card')
def business_card():
    photo_b64 = ''
    photo_path = os.path.join(os.path.dirname(__file__), 'static', 'jay_photo.jpg')
    if os.path.exists(photo_path):
        with open(photo_path, 'rb') as f:
            photo_b64 = 'data:image/jpeg;base64,' + base64.b64encode(f.read()).decode()
    return render_template('business_card.html', jay_photo_b64=photo_b64)

# ── Test Suite ────────────────────────────────────────────────────────────────
TEST_RUNS_FILE = os.path.join(os.path.dirname(__file__), 'test_runs.json')

TEST_REGISTRY = [
    {
        'name': 'FloodClaim Pro', 'url': 'https://billy-floods.up.railway.app',
        'icon': '🌊',
        'tests': [
            {'id': 'health',        'label': 'Health check',    'path': '/health',            'method': 'GET',  'expect_json': {'status': 'ok'}},
            {'id': 'homepage',      'label': 'Homepage',        'path': '/',                  'method': 'GET',  'expect_status': 200},
            {'id': 'login',         'label': 'Login page',      'path': '/login',             'method': 'GET',  'expect_status': 200},
            {'id': 'willie_claims', 'label': 'Willie API',      'path': '/willie/api/claims', 'method': 'GET',
             'headers': {'Authorization': 'Bearer S7LroZDvJSqzJZ304leqwQcxToJXRwF597gszWWarq4'}, 'expect_json_key': 'ok'},
        ]
    },
    {
        'name': 'AI Agent Widget', 'url': 'https://ai.widget.alexanderai.site',
        'icon': '🤖',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health',  'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',        'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',   'method': 'GET', 'expect_status': 200},
            {'id': 'pricing',  'label': 'Pricing page', 'path': '/pricing', 'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'EcDash', 'url': 'https://alexanderai.site',
        'icon': '🎛️',
        'tests': [
            {'id': 'homepage', 'label': 'Homepage', 'path': '/', 'method': 'GET', 'expect_status': 200},
            {'id': 'apps',     'label': 'Apps page', 'path': '/apps', 'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Pet Vet AI', 'url': 'https://pet-vet-ai-production.up.railway.app',
        'icon': '🐾',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health', 'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',       'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',  'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Contractor Pro AI', 'url': 'https://contractor.ai.solutions.alexanderai.site',
        'icon': '🔨',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health', 'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',       'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',  'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Consignment Solutions', 'url': 'https://consignment.ai.solutions.alexanderai.site',
        'icon': '🏪',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health', 'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',       'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',  'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Liberty Inventory', 'url': 'https://liberty-emporium-and-thrift-inventory-app-production.up.railway.app',
        'icon': '📋',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health', 'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',       'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',  'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Grace', 'url': 'https://moms-ai-helper.up.railway.app',
        'icon': '💜',
        'tests': [
            {'id': 'homepage',  'label': 'Homepage',  'path': '/',          'method': 'GET',  'expect_status': 200},
            {'id': 'grace_api', 'label': 'Grace AI',  'path': '/api/grace', 'method': 'POST',
             'body': {'message': 'Hello'}, 'expect_json_key': 'reply'},
        ]
    },
    {
        'name': 'Liberty Oil & Propane', 'url': 'https://liberty-oil-propane.up.railway.app',
        'icon': '🛢️',
        'tests': [
            {'id': 'homepage', 'label': 'Homepage', 'path': '/', 'method': 'GET', 'expect_status': 200},
        ]
    },
]


def run_single_test(app_url, test):
    url = app_url.rstrip('/') + test['path']
    start = time.time()
    result = {'id': test['id'], 'label': test['label'], 'url': url,
              'passed': False, 'status_code': None, 'ms': None, 'error': None, 'detail': None}
    try:
        headers = {'User-Agent': 'EcDash-TestSuite/1.0'}
        headers.update(test.get('headers', {}))
        body = test.get('body')
        data = json.dumps(body).encode() if body else None
        if data: headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, headers=headers, method=test['method'])
        with _safe_urlopen(req, timeout=10) as r:
            ms = int((time.time() - start) * 1000)
            result['ms'] = ms
            result['status_code'] = r.status
            raw = r.read().decode('utf-8', errors='replace')
            expect_status = test.get('expect_status')
            if expect_status and r.status != expect_status:
                result['error'] = f'Expected HTTP {expect_status}, got {r.status}'
                return result
            expect_json = test.get('expect_json')
            expect_json_key = test.get('expect_json_key')
            if expect_json or expect_json_key:
                try:
                    obj = json.loads(raw)
                    if expect_json:
                        for k, v in expect_json.items():
                            if obj.get(k) != v:
                                result['error'] = f'{k}={obj.get(k)!r} (want {v!r})'
                                return result
                    if expect_json_key and expect_json_key not in obj:
                        result['error'] = f'Missing key: {expect_json_key}'
                        return result
                except json.JSONDecodeError:
                    result['error'] = 'Not valid JSON'
                    return result
            result['passed'] = True
            result['detail'] = f'HTTP {r.status} · {ms}ms'
    except urllib.error.HTTPError as e:
        ms = int((time.time() - start) * 1000)
        result['ms'] = ms
        result['status_code'] = e.code
        result['error'] = f'HTTP {e.code}'
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        result['ms'] = ms
        result['error'] = str(e)[:80]
    return result


def _run_app_tests(app_entry, app_results):
    test_results = [run_single_test(app_entry['url'], t) for t in app_entry['tests']]
    passed = sum(1 for r in test_results if r['passed'])
    app_results.append({
        'name': app_entry['name'], 'url': app_entry['url'], 'icon': app_entry.get('icon', '🔵'),
        'tests': test_results, 'passed': passed, 'total': len(test_results),
        'ok': passed == len(test_results),
    })


def load_test_runs():
    if os.path.exists(TEST_RUNS_FILE):
        try:
            with open(TEST_RUNS_FILE) as f: return json.load(f)
        except: pass
    return []


def save_test_runs(runs):
    with open(TEST_RUNS_FILE, 'w') as f: json.dump(runs[:20], f, indent=2)


@app.route('/testing')
@login_required
def testing():
    return render_template('testing.html', config=config)


@app.route('/api/test-suite/run', methods=['POST'])
@login_required
def api_test_suite_run():
    app_results = []
    threads = [threading.Thread(target=_run_app_tests, args=(a, app_results)) for a in TEST_REGISTRY]
    for t in threads: t.start()
    for t in threads: t.join(timeout=15)
    name_order = {a['name']: i for i, a in enumerate(TEST_REGISTRY)}
    app_results.sort(key=lambda x: name_order.get(x['name'], 99))
    total_tests  = sum(a['total']  for a in app_results)
    total_passed = sum(a['passed'] for a in app_results)
    run = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000),
        'ran_at': datetime.datetime.utcnow().isoformat(),
        'apps': app_results,
        'summary': {
            'total_tests': total_tests, 'total_passed': total_passed,
            'total_failed': total_tests - total_passed,
            'apps_ok': sum(1 for a in app_results if a['ok']),
            'apps_total': len(app_results),
        }
    }
    runs = load_test_runs()
    runs.insert(0, run)
    save_test_runs(runs)
    return jsonify(run)


@app.route('/api/test-suite/runs', methods=['GET'])
@login_required
def api_test_suite_runs():
    runs = load_test_runs()
    return jsonify([{'id': r['id'], 'ran_at': r['ran_at'], 'summary': r.get('summary', {})} for r in runs])


@app.route('/api/test-suite/runs/<int:run_id>', methods=['GET'])
@login_required
def api_test_suite_run_get(run_id):
    for r in load_test_runs():
        if r['id'] == run_id: return jsonify(r)
    return jsonify({'error': 'not found'}), 404



# =============================================================================
# ECHO MONITORING SYSTEM
# Receives health pings + error reports from all Liberty-Emporium apps
# Writes a memory file to GitHub so Echo knows app status on every reboot
# =============================================================================

import sqlite3 as _sqlite3

MONITOR_DB_PATH = os.path.join(_DATA_DIR, 'monitor.db')

def get_monitor_db():
    db = _sqlite3.connect(MONITOR_DB_PATH)
    db.row_factory = _sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute("""
        CREATE TABLE IF NOT EXISTS health_pings (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            app      TEXT NOT NULL,
            status   TEXT NOT NULL DEFAULT 'ok',
            details  TEXT DEFAULT '{}',
            ts       TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS error_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            app        TEXT NOT NULL,
            error      TEXT NOT NULL,
            traceback  TEXT,
            route      TEXT,
            user_id    TEXT,
            extra      TEXT DEFAULT '{}',
            ts         TEXT NOT NULL,
            resolved   INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS slow_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            app      TEXT NOT NULL,
            route    TEXT,
            elapsed  REAL,
            status   INTEGER,
            ts       TEXT NOT NULL
        )
    """)
    db.commit()
    return db

def _reporter_auth(req):
    """Validate the X-Reporter-Token header."""
    token = os.environ.get('ECDASH_REPORTER_TOKEN', '')
    if not token:
        return False
    return req.headers.get('X-Reporter-Token', '') == token

# ── Ingest: health ping ───────────────────────────────────────────────────────
@app.route('/api/monitor/health', methods=['POST'])
def monitor_health_ingest():
    if not _reporter_auth(request):
        return jsonify({'error': 'unauthorized'}), 401
    d = request.get_json(silent=True) or {}
    db = get_monitor_db()
    db.execute(
        "INSERT INTO health_pings (app, status, details, ts) VALUES (?,?,?,?)",
        (d.get('app','unknown'), d.get('status','ok'),
         json.dumps(d.get('details',{})), d.get('ts', datetime.datetime.utcnow().isoformat()))
    )
    # Keep only last 500 pings per app
    db.execute("""
        DELETE FROM health_pings WHERE id NOT IN (
            SELECT id FROM health_pings WHERE app=? ORDER BY id DESC LIMIT 500
        ) AND app=?
    """, (d.get('app'), d.get('app')))
    db.commit()
    # Async: push memory to GitHub every 50 pings
    _maybe_push_memory_async()
    return jsonify({'ok': True})

# ── Ingest: error report ──────────────────────────────────────────────────────
@app.route('/api/monitor/error', methods=['POST'])
def monitor_error_ingest():
    if not _reporter_auth(request):
        return jsonify({'error': 'unauthorized'}), 401
    d = request.get_json(silent=True) or {}
    db = get_monitor_db()
    db.execute(
        "INSERT INTO error_log (app, error, traceback, route, user_id, extra, ts) VALUES (?,?,?,?,?,?,?)",
        (d.get('app','unknown'), d.get('error',''), d.get('traceback',''),
         d.get('route'), d.get('user_id'), json.dumps(d.get('extra',{})),
         d.get('ts', datetime.datetime.utcnow().isoformat()))
    )
    db.commit()
    # Always push memory on error — Jay needs to know ASAP
    threading.Thread(target=_push_memory_to_github, daemon=True).start()
    return jsonify({'ok': True})

# ── Ingest: slow request ──────────────────────────────────────────────────────
@app.route('/api/monitor/slow', methods=['POST'])
def monitor_slow_ingest():
    if not _reporter_auth(request):
        return jsonify({'error': 'unauthorized'}), 401
    d = request.get_json(silent=True) or {}
    db = get_monitor_db()
    db.execute(
        "INSERT INTO slow_log (app, route, elapsed, status, ts) VALUES (?,?,?,?,?)",
        (d.get('app','unknown'), d.get('route'), d.get('elapsed'),
         d.get('status'), d.get('ts', datetime.datetime.utcnow().isoformat()))
    )
    db.commit()
    return jsonify({'ok': True})

# ── Monitoring dashboard page ─────────────────────────────────────────────────
@app.route('/monitoring')
@login_required
def monitoring():
    db = get_monitor_db()

    # Last ping per app
    app_status = {}
    rows = db.execute("""
        SELECT app, status, ts, details FROM health_pings
        WHERE id IN (SELECT MAX(id) FROM health_pings GROUP BY app)
        ORDER BY app
    """).fetchall()
    for r in rows:
        app_status[r['app']] = {
            'status': r['status'],
            'ts': r['ts'],
            'details': json.loads(r['details'] or '{}')
        }

    # Recent errors (last 50, unresolved first)
    errors = db.execute("""
        SELECT * FROM error_log ORDER BY resolved ASC, id DESC LIMIT 50
    """).fetchall()

    # Error counts per app (last 24h)
    error_counts = {}
    rows2 = db.execute("""
        SELECT app, COUNT(*) as cnt FROM error_log
        WHERE ts >= datetime('now', '-1 day')
        GROUP BY app
    """).fetchall()
    for r in rows2:
        error_counts[r['app']] = r['cnt']

    # Slow request count per app (last 24h)
    slow_counts = {}
    rows3 = db.execute("""
        SELECT app, COUNT(*) as cnt FROM slow_log
        WHERE ts >= datetime('now', '-1 day')
        GROUP BY app
    """).fetchall()
    for r in rows3:
        slow_counts[r['app']] = r['cnt']

    return render_template('monitoring.html',
        app_status=app_status,
        errors=errors,
        error_counts=error_counts,
        slow_counts=slow_counts,
        config=config
    )

# ── Resolve error ─────────────────────────────────────────────────────────────
@app.route('/api/monitor/resolve/<int:error_id>', methods=['POST'])
@login_required
def monitor_resolve(error_id):
    db = get_monitor_db()
    db.execute("UPDATE error_log SET resolved=1 WHERE id=?", (error_id,))
    db.commit()
    return jsonify({'ok': True})

# ── Manual GitHub memory push ─────────────────────────────────────────────────
@app.route('/api/monitor/push-memory', methods=['POST'])
@login_required
def monitor_push_memory():
    threading.Thread(target=_push_memory_to_github, daemon=True).start()
    return jsonify({'ok': True, 'msg': 'Memory push started'})

# ── GitHub memory push logic ──────────────────────────────────────────────────
_last_push_time = 0
_push_counter   = 0

def _maybe_push_memory_async():
    """Push to GitHub at most once every 5 minutes."""
    global _push_counter
    _push_counter += 1
    if _push_counter % 50 == 0:
        threading.Thread(target=_push_memory_to_github, daemon=True).start()

def _push_memory_to_github():
    """Write app-status.md to the echo-v1 GitHub repo so Echo sees it on next boot."""
    global _last_push_time
    now = time.time()
    if now - _last_push_time < 60:  # max once per minute
        return
    _last_push_time = now

    gh_token = os.environ.get('GITHUB_TOKEN', '')
    if not gh_token:
        return

    try:
        db = get_monitor_db()

        # Build the markdown content
        lines = []
        lines.append("# App Network Status")
        lines.append(f"_Auto-generated by EcDash · {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_")
        lines.append("")

        # Health table
        lines.append("## App Health")
        lines.append("| App | Status | Last Seen |")
        lines.append("|-----|--------|-----------|")
        rows = db.execute("""
            SELECT app, status, ts FROM health_pings
            WHERE id IN (SELECT MAX(id) FROM health_pings GROUP BY app)
            ORDER BY app
        """).fetchall()
        for r in rows:
            icon = "✅" if r['status'] == 'ok' else "🔴"
            lines.append(f"| {r['app']} | {icon} {r['status']} | {r['ts'][:16]} |")
        if not rows:
            lines.append("| — | No pings received yet | — |")

        lines.append("")

        # Recent unresolved errors
        errors = db.execute("""
            SELECT app, error, route, ts FROM error_log
            WHERE resolved=0
            ORDER BY id DESC LIMIT 20
        """).fetchall()

        if errors:
            lines.append("## ⚠️ Active Errors (needs attention)")
            for e in errors:
                lines.append(f"- **{e['app']}** | `{e['route'] or 'unknown route'}` | {e['ts'][:16]}")
                lines.append(f"  > {e['error'][:200]}")
        else:
            lines.append("## ✅ No Active Errors")
            lines.append("All apps reporting clean.")

        lines.append("")

        # 24h error counts
        counts = db.execute("""
            SELECT app, COUNT(*) as cnt FROM error_log
            WHERE ts >= datetime('now', '-1 day') AND resolved=0
            GROUP BY app ORDER BY cnt DESC
        """).fetchall()
        if counts:
            lines.append("## Error Count (last 24h)")
            for c in counts:
                lines.append(f"- {c['app']}: {c['cnt']} error(s)")
            lines.append("")

        content = "\n".join(lines)

        # GitHub API: get current file SHA if it exists
        api_base = "https://api.github.com/repos/Liberty-Emporium/echo-v1/contents/memory/app-status.md"
        headers  = {
            "Authorization": f"token {gh_token}",
            "Accept":        "application/vnd.github.v3+json",
            "Content-Type":  "application/json",
        }

        sha = None
        try:
            get_req = urllib.request.Request(api_base, headers=headers, method='GET')
            with _safe_urlopen(get_req, timeout=8) as resp:
                existing = json.loads(resp.read())
                sha = existing.get('sha')
        except Exception:
            pass  # File doesn't exist yet — that's fine

        import base64 as _b64
        payload = {
            "message": f"chore: update app-status.md [{datetime.datetime.utcnow().strftime('%H:%M UTC')}]",
            "content": _b64.b64encode(content.encode('utf-8')).decode('utf-8'),
            "branch":  "main",
        }
        if sha:
            payload["sha"] = sha

        put_req = urllib.request.Request(
            api_base,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='PUT'
        )
        with _safe_urlopen(put_req, timeout=10):
            pass

    except Exception:
        pass  # Never crash EcDash over a memory push


if __name__ == '__main__':
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
    app.run(host='0.0.0.0', port=5000, debug=False)

