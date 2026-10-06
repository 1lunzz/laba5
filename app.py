import hmac
import os
import re
import sqlite3
from functools import wraps

from flask import Flask, g, jsonify, request


def create_app(database=None):
    app = Flask(__name__)
    app.config.update(DATABASE=database or os.environ.get('DB_PATH', 'users.db'),
                      MAX_CONTENT_LENGTH=16384)
    user_token = os.environ['USER_TOKEN']
    admin_token = os.environ['ADMIN_TOKEN']
    if min(len(user_token), len(admin_token)) < 32 or user_token == admin_token:
        raise ValueError('Use different tokens of at least 32 characters')

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    with app.app_context():
        db().execute('CREATE TABLE IF NOT EXISTS users ('
                     'id INTEGER PRIMARY KEY, name TEXT NOT NULL, '
                     'email TEXT NOT NULL UNIQUE)')
        db().commit()
        g.pop('db').close()

    @app.teardown_appcontext
    def close_db(error):
        connection = g.pop('db', None)
        if connection is not None:
            connection.close()

    def protected(admin=False):
        def decorate(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                header = request.headers.get('Authorization', '')
                token = header[7:] if header.startswith('Bearer ') else ''
                is_admin = hmac.compare_digest(token, admin_token)
                is_user = hmac.compare_digest(token, user_token)
                if not (is_admin or is_user):
                    return jsonify(error='Unauthorized'), 401
                if admin and not is_admin:
                    return jsonify(error='Forbidden'), 403
                return function(*args, **kwargs)
            return wrapped
        return decorate

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/health')
    def health():
        return jsonify(status='ok')

    @app.get('/api/users')
    @protected()
    def get_users():
        rows = db().execute('SELECT id, name, email FROM users ORDER BY id').fetchall()
        return jsonify([dict(row) for row in rows])

    @app.post('/api/users')
    @protected(admin=True)
    def add_user():
        if not request.is_json:
            return jsonify(error='JSON required'), 415
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {'name', 'email'}:
            return jsonify(error='Invalid fields'), 400
        name, email = data['name'], data['email']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-zА-Яа-яЁё -]{1,80}', name):
            return jsonify(error='Invalid name'), 400
        if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r'[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
            return jsonify(error='Invalid email'), 400
        try:
            cursor = db().execute('INSERT INTO users(name,email) VALUES (?,?)', (name, email))
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify(error='Email already exists'), 409
        return jsonify(id=cursor.lastrowid, name=name, email=email), 201

    @app.delete('/api/users/<int:user_id>')
    @protected(admin=True)
    def delete_user(user_id):
        cursor = db().execute('DELETE FROM users WHERE id=?', (user_id,))
        db().commit()
        if not cursor.rowcount:
            return jsonify(error='Not found'), 404
        return '', 204

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
