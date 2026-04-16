import base64
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
