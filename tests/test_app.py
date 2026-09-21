from __future__ import annotations

from io import BytesIO
from pathlib import Path

from werkzeug.security import generate_password_hash

from app import create_app
from src.config import ConfigForTests


def login(client):
    token_resp = client.get('/login')
    # Simple token extraction from rendered HTML for tests.
    html = token_resp.get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    token = html.split(marker)[1].split('"')[0]
    return client.post('/login', data={'username': 'admin', 'password': 'StrongPassword123!', 'csrf_token': token}, follow_redirects=True)


def test_dashboard_requires_login(tmp_path: Path):
    cfg = ConfigForTests.build(tmp_path, generate_password_hash('StrongPassword123!'))
    app = create_app(cfg)
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 302
    assert '/login' in response.location


def test_login_and_security_headers(tmp_path: Path):
    cfg = ConfigForTests.build(tmp_path, generate_password_hash('StrongPassword123!'))
    app = create_app(cfg)
    client = app.test_client()
    response = login(client)
    assert response.status_code == 200
    assert response.headers['X-Frame-Options'] == 'DENY'


def test_upload_rejects_python_file(tmp_path: Path):
    cfg = ConfigForTests.build(tmp_path, generate_password_hash('StrongPassword123!'))
    app = create_app(cfg)
    client = app.test_client()
    login(client)
    csrf = client.session_transaction().__enter__().get('csrf_token')
    response = client.post('/upload', data={'csrf_token': csrf, 'threshold': '5', 'log_file': (BytesIO(b'print(1)'), 'evil.py')}, content_type='multipart/form-data', follow_redirects=True)
    assert b'Only .log and .txt files are allowed' in response.data


def test_api_analyze_accepts_log(tmp_path: Path):
    cfg = ConfigForTests.build(tmp_path, generate_password_hash('StrongPassword123!'))
    app = create_app(cfg)
    client = app.test_client()
    login(client)
    with client.session_transaction() as sess:
        csrf = sess['csrf_token']
    payload = b'2026-05-01 10:00:00 IP=10.0.0.1 USER=admin ACTION=login STATUS=failed\n' * 5
    response = client.post('/api/analyze', data={'csrf_token': csrf, 'threshold': '3', 'log_file': (BytesIO(payload), 'auth.log')}, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['result']['suspicious_ips'][0]['ip'] == '10.0.0.1'
