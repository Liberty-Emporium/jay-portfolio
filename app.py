import base64
import os
import json
import datetime
import urllib.request
import urllib.error
import time
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, session as flask_session, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'portfolio-secret-2026')

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')
TODOS_FILE   = os.path.join(os.path.dirname(__file__), 'todos.json')
TICKETS_FILE = os.path.join(os.path.dirname(__file__), 'tickets.json')

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

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not flask_session.get('dashboard_auth'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if pw == DASHBOARD_PASSWORD:
            flask_session['dashboard_auth'] = True
            flask_session.permanent = True
            return redirect(url_for('dashboard'))
        error = 'Wrong password. Try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    flask_session.pop('dashboard_auth', None)
    return redirect(url_for('index'))

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
    {'name': 'Jay Portfolio',         'url': 'https://jay-portfolio-production.up.railway.app'},
    {'name': 'Liberty Inventory',     'url': 'https://liberty-emporium-and-thrift-inventory-app-production.up.railway.app'},
    {'name': 'Inventory Demo',        'url': 'https://liberty-emporium-inventory-demo-app-production.up.railway.app'},
    {'name': 'Keep Your Secrets',     'url': 'https://ai-api-tracker-production.up.railway.app'},
    {'name': 'Pet Vet AI',            'url': 'https://pet-vet-ai-production.up.railway.app'},
    {'name': 'GymForge',              'url': 'https://web-production-1c23.up.railway.app'},
    {'name': 'Contractor Pro AI',     'url': 'https://contractor-pro-ai-production.up.railway.app'},
    {'name': 'Dropship Shipping',     'url': 'https://dropship-shipping-production.up.railway.app'},
    {'name': 'Consignment Solutions', 'url': 'https://web-production-43ce4.up.railway.app'},
]

def ping_app(app_entry, results):
    url = app_entry['url']
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'EchoHealthCheck/1.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
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

    base = """You are Echo — the personal AI executive assistant for Jay Alexander, founder of Liberty-Emporium / Alexander AI Integrated Solutions.
You are accessed via the Command Center dashboard at jay-portfolio-production.up.railway.app.
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
                 'HTTP-Referer': 'https://jay-portfolio-production.up.railway.app',
                 'X-Title': 'Echo - Jay Alexander Command Center'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return jsonify({'reply': result['choices'][0]['message']['content']})
    except Exception as e:
        return jsonify({'reply': f'Echo is unavailable right now. Error: {str(e)[:100]}'})

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

if __name__ == '__main__':
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
    app.run(host='0.0.0.0', port=5000, debug=True)
