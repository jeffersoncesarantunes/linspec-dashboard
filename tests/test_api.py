import os, sys, json, tempfile, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import app as dash

@pytest.fixture
def client():
    dash.app.config['TESTING'] = True
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    dash.DB = db_path
    dash.init_db()
    with dash.app.test_client() as c:
        yield c
    os.unlink(db_path)
    # reset rate limiter
    dash._request_times.clear()

def test_dashboard_returns_200(client):
    rv = client.get('/')
    assert rv.status_code == 200

def test_subscribe_valid(client):
    rv = client.post('/api/subscribe', data={
        'name': 'Test', 'email': 'test@example.com'
    })
    assert rv.status_code == 302

def test_subscribe_invalid_email(client):
    rv = client.post('/api/subscribe', data={
        'name': 'Test', 'email': 'invalid'
    })
    assert rv.status_code == 302

def test_subscribe_missing_fields(client):
    rv = client.post('/api/subscribe', data={'name': ''})
    assert rv.status_code == 302

def test_scan_requires_api_key(client):
    rv = client.post('/api/scan', json={})
    assert rv.status_code == 401

def test_scan_without_json(client):
    with dash.get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, label) VALUES (?, ?)",
            ('test-key-nojson', 'test')
        ).connection.commit()
    rv = client.post('/api/scan', data='not json',
                     content_type='application/json',
                     headers={'X-API-Key': 'test-key-nojson'})
    assert rv.status_code == 400

def test_scan_detail_not_found(client):
    rv = client.get('/scan/9999')
    assert rv.status_code == 404

def test_raw_scan_not_found(client):
    rv = client.get('/api/scan/9999/raw')
    assert rv.status_code == 404

def test_rate_limit_exceeded(client):
    dash.RATE_LIMIT = 2
    for _ in range(2):
        client.post('/api/subscribe', data={
            'name': 'T', 'email': 't@t.com'
        })
    rv = client.post('/api/subscribe', data={
        'name': 'T', 'email': 't2@t.com'
    })
    assert rv.status_code == 429

def test_admin_setup_creates_key(client):
    rv = client.get('/admin/setup')
    assert rv.status_code == 200
    assert 'API Key' in rv.data.decode()

def test_admin_setup_idempotent(client):
    client.get('/admin/setup')
    rv = client.get('/admin/setup')
    assert rv.status_code == 200
    assert 'ja existe' in rv.data.decode().lower()

def test_valid_scan_submission(client):
    with dash.get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, label) VALUES (?, ?)",
            ('test-key-123', 'test')
        ).connection.commit()
    payload = {
        'hostname': 'testbox',
        'kernel': '6.8.0',
        'os': 'Linux',
        'checks': [
            {'check': 'aslr', 'category': 'memory', 'status': 'PASS', 'message': 'ok'},
            {'check': 'kptr', 'category': 'kernel', 'status': 'VULN', 'message': 'bad'},
        ]
    }
    rv = client.post('/api/scan', json=payload,
                     headers={'X-API-Key': 'test-key-123'})
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data['status'] == 'ok'
    assert data['score'] == 50.0

def test_empty_checks_scan(client):
    with dash.get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, label) VALUES (?, ?)",
            ('test-key-456', 'test')
        ).connection.commit()
    rv = client.post('/api/scan', json={'checks': []},
                     headers={'X-API-Key': 'test-key-456'})
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data['score'] == 0.0
