import sqlite3
import pytest
from app import create_app
from vulnerable_app import create_app as vulnerable

USER = 'u' * 40
ADMIN = 'a' * 40
AUTH = {'Authorization': 'Bearer ' + ADMIN}
READ = {'Authorization': 'Bearer ' + USER}
PAYLOAD = {'name': 'Alice', 'email': 'alice@example.test'}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('USER_TOKEN', USER)
    monkeypatch.setenv('ADMIN_TOKEN', ADMIN)
    app = create_app(str(tmp_path / 'safe.db'))
    app.config['TESTING'] = True
    return app.test_client()


def test_crud(client):
    result = client.post('/api/users', json=PAYLOAD, headers=AUTH)
    assert result.status_code == 201
    uid = result.json['id']
    assert client.get('/api/users', headers=READ).json[0]['name'] == 'Alice'
    assert client.delete(f'/api/users/{uid}', headers=AUTH).status_code == 204
    assert client.get('/api/users', headers=READ).json == []


@pytest.mark.parametrize('method,url', [('get', '/api/users'), ('post', '/api/users'), ('delete', '/api/users/1')])
def test_no_auth(client, method, url):
    assert getattr(client, method)(url, json=PAYLOAD).status_code == 401


@pytest.mark.parametrize('method,url', [('post', '/api/users'), ('delete', '/api/users/1')])
def test_user_cannot_write(client, method, url):
    assert getattr(client, method)(url, json=PAYLOAD, headers=READ).status_code == 403


@pytest.mark.parametrize('name', ["Eve', 'x'); DROP TABLE users; --", '<script>alert(1)</script>'])
def test_injection_blocked(client, name):
    assert client.post('/api/users', json={'name': name, 'email': 'x@example.test'}, headers=AUTH).status_code == 400
    assert client.post('/api/users', json=PAYLOAD, headers=AUTH).status_code == 201
    assert len(client.get('/api/users', headers=READ).json) == 1


@pytest.mark.parametrize('data', [[], {'name': 1, 'email': 'x@example.test'}, dict(PAYLOAD, role='admin')])
def test_bad_fields(client, data):
    assert client.post('/api/users', json=data, headers=AUTH).status_code == 400


def test_duplicate(client):
    client.post('/api/users', json=PAYLOAD, headers=AUTH)
    assert client.post('/api/users', json=PAYLOAD, headers=AUTH).status_code == 409


def test_headers(client):
    result = client.get('/api/users', headers=READ)
    assert result.mimetype == 'application/json'
    assert result.headers['X-Content-Type-Options'] == 'nosniff'
    assert result.headers['Cache-Control'] == 'no-store'


def test_missing(client):
    assert client.delete('/api/users/999', headers=AUTH).status_code == 404


def test_vulnerable_sql(tmp_path):
    path = str(tmp_path / 'unsafe.db')
    client = vulnerable(path).test_client()
    attack = {'name': "Eve', 'x'); DROP TABLE users; --", 'email': 'x@example.test'}
    assert client.post('/api/users', json=attack).status_code == 201
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone() is None


def test_vulnerable_access(tmp_path):
    client = vulnerable(str(tmp_path / 'unsafe.db')).test_client()
    assert client.post('/api/users', json=PAYLOAD).status_code == 201
    assert client.delete('/api/users/1').status_code == 204


def test_vulnerable_headers(tmp_path):
    result = vulnerable(str(tmp_path / 'unsafe.db')).test_client().get('/api/users')
    assert 'X-Content-Type-Options' not in result.headers


def test_parameter_binding(client):
    path = client.application.config['DATABASE']
    with sqlite3.connect(path) as connection:
        text = "Eve', 'x'); DROP TABLE users; --"
        connection.execute('INSERT INTO users(name,email) VALUES (?,?)', (text, 'x@example.test'))
        assert connection.execute('SELECT name FROM users').fetchone()[0] == text
