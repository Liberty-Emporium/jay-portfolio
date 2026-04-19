import base64
import os
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session as flask_session, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'portfolio-secret-2026')

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

DEFAULT_CONFIG = {
    "photo": "👨‍💻",
    "name": "Jay Alexander",
    "tagline": "Building the Future with AI & Code",
    "email": "jay@libertyemporium.com",
    "github": "Liberty-Emporium",
    "photo_url": ""
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Load config at startup
config = load_config()

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
    name    = request.form.get('name', '').strip()
    email   = request.form.get('email', '').strip()
    interest = request.form.get('interest', '')
    message = request.form.get('message', '').strip()
    # Log to a file so Jay never misses an inquiry
    import datetime
    log_path = os.path.join(os.path.dirname(__file__), 'investor_inquiries.log')
    with open(log_path, 'a') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Date: {datetime.datetime.now()}\n")
        f.write(f"Name: {name}\nEmail: {email}\nInterest: {interest}\nMessage: {message}\n")
    flash(f'Thanks {name}! Jay will get back to you at {email} within 24 hours.', 'success')
    return redirect(url_for('investors') + '#contact')

@app.route('/tools')
def tools():
    return render_template('tools.html')

# ── Todos ────────────────────────────────────────────
TODOS_FILE = os.path.join(os.path.dirname(__file__), 'todos.json')

def load_todos():
    if os.path.exists(TODOS_FILE):
        try:
            with open(TODOS_FILE) as f:
                return json.load(f)
        except:
            pass
    return []

def save_todos(todos):
    with open(TODOS_FILE, 'w') as f:
        json.dump(todos, f, indent=2)

@app.route('/api/todos', methods=['GET'])
@login_required
def api_todos_get():
    return jsonify(load_todos())

@app.route('/api/todos', methods=['POST'])
@login_required
def api_todos_add():
    data = request.get_json()
    todos = load_todos()
    todo = {
        'id': int(datetime.datetime.utcnow().timestamp() * 1000),
        'text': data.get('text', '').strip(),
        'priority': data.get('priority', 'medium'),
        'done': False,
        'created': datetime.datetime.utcnow().isoformat()
    }
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
    todos = load_todos()
    todos = [t for t in todos if t['id'] != todo_id]
    save_todos(todos)
    return jsonify({'ok': True})

# ── Auth ─────────────────────────────────────────────────
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
        else:
            error = 'Wrong password. Try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    flask_session.pop('dashboard_auth', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', config=config)

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
    # Jay's photo - base64 embedded
    import os
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
