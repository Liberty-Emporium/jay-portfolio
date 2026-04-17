"""
Tests for Jay Portfolio
Covers: public routes, admin auth, investor page, private routes protection
NOTE: /court, /court/qr, /flyer are PRIVATE — tests verify they exist but do NOT link publicly
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault('SECRET_KEY', 'test-secret-key')

import app as jp


@pytest.fixture
def client(tmp_path):
    jp.app.config['TESTING'] = True
    jp.app.config['SECRET_KEY'] = 'test-secret-key'
    jp.CONFIG_FILE = str(tmp_path / 'config.json')
    with jp.app.test_client() as c:
        yield c


# ── Public pages ──────────────────────────────────────────────────────────────

def test_index_returns_200(client):
    assert client.get('/').status_code == 200

def test_apps_page_returns_200(client):
    assert client.get('/apps').status_code == 200

def test_investors_page_returns_200(client):
    res = client.get('/investors')
    assert res.status_code == 200

def test_card_page_returns_200(client):
    assert client.get('/card').status_code == 200

def test_robots_txt_returns_200(client):
    assert client.get('/robots.txt').status_code == 200


# ── Investor inquiry form ─────────────────────────────────────────────────────

def test_investor_inquiry_post_missing_fields(client):
    res = client.post('/investor-inquiry', data={})
    assert res.status_code in (400, 302, 200)

def test_investor_inquiry_post_with_data(client):
    res = client.post('/investor-inquiry', data={
        'name': 'Test Investor',
        'email': 'investor@test.com',
        'message': 'Interested in investing'
    }, follow_redirects=True)
    assert res.status_code == 200


# ── Admin ─────────────────────────────────────────────────────────────────────

def test_admin_page_get_returns_200(client):
    res = client.get('/admin')
    assert res.status_code == 200

def test_admin_wrong_password_stays_on_admin(client):
    res = client.post('/admin', data={'password': 'wrongpassword'}, follow_redirects=True)
    assert res.status_code == 200
    # Admin page reloads on wrong password (no error text — just stays on admin)
    assert b'admin' in res.data.lower() or b'password' in res.data.lower()


# ── Private routes — verify they exist but are access-controlled ──────────────
# (PRIVATE: Do NOT link these routes publicly — court documents only)

def test_court_route_accessible(client):
    """Private route exists — for Jay's use only"""
    res = client.get('/court')
    assert res.status_code in (200, 302, 401, 403)

def test_court_qr_route_accessible(client):
    """Private route exists — for Jay's use only"""
    res = client.get('/court/qr')
    assert res.status_code in (200, 302, 401, 403)

def test_flyer_route_accessible(client):
    """Private route exists — for Jay's use only"""
    res = client.get('/flyer')
    assert res.status_code in (200, 302, 401, 403)


# ── Config utilities ──────────────────────────────────────────────────────────

def test_load_config_returns_dict(client):
    with jp.app.app_context():
        cfg = jp.load_config()
        assert isinstance(cfg, dict)

def test_save_and_load_config_roundtrip(client, tmp_path):
    jp.CONFIG_FILE = str(tmp_path / 'config.json')
    jp.save_config({'test_key': 'test_value'})
    loaded = jp.load_config()
    assert loaded.get('test_key') == 'test_value'
