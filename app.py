import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash

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
        "User-agent: *\nAllow: /\nDisallow: /tools\nDisallow: /admin\n",
        mimetype="text/plain")

@app.route('/tools')
def tools():
    return render_template('tools.html')

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

if __name__ == '__main__':
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
    app.run(host='0.0.0.0', port=5000, debug=True)
