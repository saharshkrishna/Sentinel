"""
main.py - Entry point for SentinelAI Log Analyzer.

Starts the log analysis engine in a background thread, then runs
the Flask-SocketIO server.
"""

import threading
from app import create_app
from app.routes import run_analyzer

if __name__ == '__main__':
    app, socketio, analyzer = create_app()

    # Start log analysis engine in a background daemon thread
    analyzer_thread = threading.Thread(
        target=run_analyzer,
        args=(analyzer,),
        daemon=True
    )
    analyzer_thread.start()

    # Start Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
