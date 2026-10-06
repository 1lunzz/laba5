"""Deliberately vulnerable local laboratory fixture. Never deploy."""
import sqlite3
from flask import Flask, jsonify, request


def create_app(database):
    app = Flask(__name__)
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT)')

    @app.post('/api/users')
    def add_user():
        data = request.get_json()
        query = "INSERT INTO users(name,email) VALUES ('%s','%s')" % (data['name'], data['email'])
        with sqlite3.connect(database) as connection:
            connection.executescript(query)
        return jsonify(status='created'), 201

    @app.get('/api/users')
    def get_users():
        with sqlite3.connect(database) as connection:
            rows = connection.execute('SELECT id,name,email FROM users').fetchall()
        return jsonify(rows)

    @app.delete('/api/users/<int:user_id>')
    def delete_user(user_id):
        with sqlite3.connect(database) as connection:
            connection.execute('DELETE FROM users WHERE id=?', (user_id,))
        return '', 204

    return app


if __name__ == '__main__':
    create_app('vulnerable.db').run(host='127.0.0.1', debug=True)
