"""
app/__init__.py - Flask application factory.

Creates the Flask app and SocketIO instance, then registers all routes.
Import `create_app` from here in main.py.
"""

import logging
from flask import Flask
from flask_socketio import SocketIO

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Shared SocketIO instance (must be created before routes import it)
socketio = SocketIO()


def create_app(ollama_url: str = "http://localhost:11434") -> tuple:
    """
    Application factory.

    Returns:
        (Flask app, SocketIO instance, LogAnalyzer instance)
    """
    from app.analyzer import LogAnalyzer
    from app.routes import register_routes

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'cybersecurity-log-analyzer-secret'

    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')

    analyzer = LogAnalyzer(ollama_url=ollama_url)
    register_routes(app, socketio, analyzer)

    return app, socketio, analyzer
