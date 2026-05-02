#!/usr/bin/env python3
"""
One-time migration: seed the vault DB with the legacy hardcoded credentials
that used to live in dashboard.html.

Run from the project root:
    python3 scripts/migrate_credentials.py

Only inserts if vault is empty. Safe to re-run.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Minimal bootstrap so we can import app
os.environ.setdefault('RAILWAY_VOLUME_MOUNT_PATH', '/data')

try:
    from app import get_vault_db, vault_encrypt, app
except Exception as e:
    print(f"Import error: {e}")
    sys.exit(1)

LEGACY_CREDS = [
    # (category, label, username, secret, url, notes)
    ("EcDash", "EcDash Dashboard Password", "", "SET_FROM_RAILWAY_ENV", "https://jay-portfolio-production.up.railway.app", "Set DASHBOARD_PASSWORD in Railway to change"),
    ("AI Agent Widget", "AI Agent Widget Admin Email", "alexanderjay70@gmail.com", "alexanderjay70@gmail.com", "https://ai.widget.alexanderai.site/dashboard", ""),
    ("AI Agent Widget", "AI Agent Widget Password", "alexanderjay70@gmail.com", "Treetop121570!", "https://ai.widget.alexanderai.site/dashboard", ""),
    ("Stripe", "Stripe Public Key", "", "pk_live_...", "", "Get from Stripe dashboard — pk_live_"),
    ("Stripe", "Stripe Secret Key", "", "sk_live_...", "", "Set STRIPE_SECRET_KEY in Railway for each app"),
    ("Railway", "Railway API Token", "", "see /root/.secrets/railway_token", "", "Workspace: liberty-emporium's Projects"),
    ("GitHub", "GitHub PAT", "", "see /root/.secrets/github_token", "https://github.com/Liberty-Emporium", "Rotates — Jay provides fresh token each session"),
    ("GitLab", "GitLab PAT", "", "see /root/.secrets/gitlab_token", "https://gitlab.com/Liberty-Emporium", "Backup mirror only"),
    ("GymForge", "GymForge Owner Login", "jay@gymforge.com", "GymForge2026!", "https://web-production-1c23.up.railway.app", "Demo owner account"),
    ("GymForge", "GymForge Demo Password", "<role>@demo.gymforge.com", "Demo2026!", "https://web-production-1c23.up.railway.app", "manager/trainer/front_desk/cleaner/nutritionist/member"),
    ("FloodClaim Pro", "FloodClaim Pro URL", "", "https://billy-floods.up.railway.app", "https://billy-floods.up.railway.app/sales", "Sales page at /sales"),
    ("Sweet Spot Cakes", "Sweet Spot URL", "", "https://sweet-spot-cakes.up.railway.app", "https://sweet-spot-cakes.up.railway.app", "CRITICAL — revenue app, zero downtime"),
    ("OpenRouter", "OpenRouter API Key", "", "SET_FROM_RAILWAY_ENV", "https://openrouter.ai", "Get from openrouter.ai — set OPENROUTER_API_KEY in Railway"),
]

with app.app_context():
    db = get_vault_db()
    count = db.execute('SELECT COUNT(*) FROM secrets').fetchone()[0]
    if count > 0:
        print(f"Vault already has {count} entries — skipping migration")
        db.close()
        sys.exit(0)

    for cat, label, username, secret, url, notes in LEGACY_CREDS:
        encrypted = vault_encrypt(secret)
        db.execute(
            'INSERT INTO secrets(category,label,username,secret,url,notes) VALUES(?,?,?,?,?,?)',
            (cat, label, username, encrypted, url, notes)
        )
        print(f"  ✅ {cat} / {label}")

    db.commit()
    db.close()
    print(f"\n✅ Migrated {len(LEGACY_CREDS)} legacy credentials into vault")
