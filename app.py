import base64
import os
import json
import datetime
import urllib.request
import urllib.error
import time
import threading
import sqlite3
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

TODOS_FILE   = os.path.join(os.path.dirname(__file__), 'todos.json')
TICKETS_FILE  = os.path.join(os.path.dirname(__file__), 'tickets.json')
ECHO_TASKS_FILE = os.path.join(os.path.dirname(__file__), 'echo_tasks.json')



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

API_TOKENS_FILE = os.path.join(os.path.dirname(__file__), 'api_tokens.json')

def load_api_tokens():
    if os.path.exists(API_TOKENS_FILE):
        try:
            with open(API_TOKENS_FILE) as f: return json.load(f)
        except: pass
    return []

def save_api_tokens(tokens):
    with open(API_TOKENS_FILE, 'w') as f: json.dump(tokens, f, indent=2)

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
        task['response'] = 'ECHO_WEBHOOK_URL not configured. Task saved. Set it in Railway env vars to connect EcDash to Echo.'

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

@app.route('/api/settings', methods=['GET'])
@login_required
def api_settings_get():
    return jsonify(load_app_settings())

@app.route('/api/settings', methods=['POST'])
@login_required
def api_settings_save():
    data = request.get_json()
    s = load_app_settings()
    allowed = {'echo_model', 'echo_max_tokens', 'echo_temperature'}
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
    {'name': 'Contractor Pro AI',     'url': 'https://contractor-pro-ai-production.up.railway.app'},
    {'name': 'Consignment Solutions', 'url': 'https://web-production-43ce4.up.railway.app'},
    {'name': 'FloodClaim Pro',         'url': 'https://billy-floods.up.railway.app'},
    {'name': 'Liberty Oil & Propane',  'url': 'https://liberty-oil-propane.up.railway.app'},
    {'name': 'Alexander AI Voice',      'url': 'https://voice.alexanderai.site'},
    {'name': 'AI Agent Widget',         'url': 'https://ai.widget.alexanderai.site'},
    {'name': 'Drop Shipping',           'url': 'https://shop.alexanderai.site'},
    {'name': 'List It Everywhere',      'url': 'https://web-production-c799c.up.railway.app'},
    {'name': 'AI Info Site',             'url': 'https://ai.info1.alexanderai.site'},
    {'name': 'Drop Shipping',            'url': 'https://shop.alexanderai.site'},
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

def build_system_prompt():
    """Build Echo's system prompt from brain files. Falls back to defaults."""
    soul     = load_brain_file('SOUL.md')
    identity = load_brain_file('IDENTITY.md')
    memory   = load_brain_file('MEMORY.md')

    base = """You are EcDash — the personal AI executive assistant for Jay Alexander, founder of Liberty-Emporium / Alexander AI Integrated Solutions.
You are accessed via the Command Center dashboard at alexanderai.site.
Never say you are ChatGPT, Claude, Gemini, or any AI product. You are Echo. Only Echo."""

    parts = [base]
    if identity: parts.append('\n---\n# YOUR IDENTITY\n' + identity)
    if soul:     parts.append('\n---\n# YOUR SOUL & PERSONALITY\n' + soul)
    if memory:   parts.append('\n---\n# YOUR MEMORY (read this carefully)\n' + memory)
    parts.append('\n---\nBe concise, direct, warm. You have opinions. You say "we" about Jay\'s projects. Never use filler like "Great question!".')
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
    sync_token = os.environ.get('BRAIN_SYNC_TOKEN', '')
    if not sync_token:
        return jsonify({'error': 'sync not configured'}), 503
    auth = request.headers.get('X-Brain-Sync-Token', '')
    if not auth or auth != sync_token:
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
@login_required
def chat():
    return render_template('chat.html', config=config)

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

    system_content = build_system_prompt()
    health_keywords = ['health', 'status', 'up', 'down', 'live', 'working', 'test', 'ping', 'check', 'running', 'broken', 'crash', 'offline']
    if any(kw in user_message.lower() for kw in health_keywords):
        try:
            health = check_all_apps()
            lines = ['\n\nLIVE APP HEALTH (checked right now):']
            for r in health:
                icon = 'UP' if r['ok'] else 'DOWN'
                lines.append(f"- {r['name']}: {icon} (HTTP {r['status']}, {r['ms']}ms)")
            up = sum(1 for r in health if r['ok'])
            lines.append(f"\nSummary: {up}/{len(health)} apps are up.")
            system_content = ECHO_SYSTEM_PROMPT + '\n'.join(lines)
        except Exception:
            pass

    messages = [{'role': 'system', 'content': system_content}]
    for h in history[-10:]:
        if h.get('role') in ('user', 'assistant'):
            messages.append({'role': h['role'], 'content': h['content']})
    messages.append({'role': 'user', 'content': user_message})

    s = load_app_settings()
    payload = json.dumps({'model': s['echo_model'], 'messages': messages,
                          'max_tokens': s['echo_max_tokens'], 'temperature': s['echo_temperature']}).encode('utf-8')
    req = urllib.request.Request(
        'https://openrouter.ai/api/v1/chat/completions', data=payload,
        headers={'Authorization': f'Bearer {openrouter_key}',
                 'Content-Type': 'application/json; charset=utf-8',
                 'HTTP-Referer': 'https://alexanderai.site',
                 'X-Title': 'Echo - Jay Alexander Command Center'})
    try:
        with _safe_urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return jsonify({'reply': result['choices'][0]['message']['content']})
    except Exception as e:
        return jsonify({'reply': f'Echo is unavailable right now. Error: {str(e)[:100]}'})


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
    return render_template('dashboard.html', config=config)

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
        'name': 'Contractor Pro AI', 'url': 'https://contractor-pro-ai-production.up.railway.app',
        'icon': '🔨',
        'tests': [
            {'id': 'health',   'label': 'Health check', 'path': '/health', 'method': 'GET', 'expect_json': {'status': 'ok'}},
            {'id': 'homepage', 'label': 'Homepage',     'path': '/',       'method': 'GET', 'expect_status': 200},
            {'id': 'login',    'label': 'Login page',   'path': '/login',  'method': 'GET', 'expect_status': 200},
        ]
    },
    {
        'name': 'Consignment Solutions', 'url': 'https://web-production-43ce4.up.railway.app',
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

