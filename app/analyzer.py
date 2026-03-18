"""
analyzer.py - Core log analysis engine orchestrating rule matching,
              AI analysis, IP tracking, and alert management.
"""

import asyncio
import hashlib
import logging
import os
import queue
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable, List, Optional

import aiofiles

from app.models import Alert, AttackCategory, Severity
from app.rules import RULES_DATABASE
from app.buffer import LogBuffer
from app.stats import StatisticsTracker
from app.ai_analyzer import OllamaAnalyzer

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Main log analysis engine."""

    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.rules = RULES_DATABASE
        self.alerts: List[Alert] = []
        self.alert_queue: queue.Queue = queue.Queue()
        self.buffer = LogBuffer()
        self.stats = StatisticsTracker()
        self.ai_analyzer = OllamaAnalyzer(base_url=ollama_url)
        self.running = False
        self.alert_callbacks: List[Callable] = []

        # IP reputation cache
        self.suspicious_ips = defaultdict(lambda: {'count': 0, 'first_seen': None, 'alerts': []})

    def register_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)

    def extract_ip(self, log_line: str) -> Optional[str]:
        """Extract the first IP address found in a log line."""
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        return match.group(0) if match else None

    def calculate_confidence(self, rule, log_line: str, ip: Optional[str]) -> float:
        """Calculate confidence score based on multiple contextual factors."""
        indicators = 0.0

        if re.search(r'(?i)(admin|root|system)', log_line):
            indicators += 0.1
        if re.search(r'(?i)(error|fail|denied)', log_line):
            indicators += 0.1
        if ip and self.suspicious_ips[ip]['count'] > 3:
            indicators += 0.2

        # Time-based correlation
        if ip and self.suspicious_ips[ip]['alerts']:
            last_alert = self.suspicious_ips[ip]['alerts'][-1]
            if (datetime.now() - last_alert).total_seconds() < 300:
                indicators += 0.1

        return min(0.7 + indicators, 1.0)

    async def analyze_line(self, log_line: str) -> List[Alert]:
        """Analyze a single log line against all rules and optionally AI."""
        alerts: List[Alert] = []
        self.buffer.add(log_line)
        self.stats.increment_logs()

        ip = self.extract_ip(log_line)

        # Rule-based detection
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.pattern.search(log_line):
                confidence = self.calculate_confidence(rule, log_line, ip)
                alert = Alert(
                    id=hashlib.md5(f"{log_line}{rule.id}{time.time()}".encode()).hexdigest()[:12],
                    timestamp=datetime.now(),
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    source_ip=ip,
                    target=None,
                    raw_log=log_line[:500],
                    confidence=confidence,
                    mitre_technique=rule.mitre_id
                )

                if ip:
                    if self.suspicious_ips[ip]['first_seen'] is None:
                        self.suspicious_ips[ip]['first_seen'] = datetime.now()
                    self.suspicious_ips[ip]['count'] += 1
                    self.suspicious_ips[ip]['alerts'].append(datetime.now())

                alerts.append(alert)
                self.stats.update(alert)

        # AI analysis — only when no rule matched (reduces noise)
        if len(alerts) == 0:
            ai_result = await self.ai_analyzer.analyze(log_line, self.buffer.get_context())
            if ai_result and ai_result.get('is_threat') and ai_result.get('confidence', 0) > 0.8:
                alert = Alert(
                    id=hashlib.md5(f"{log_line}AI{time.time()}".encode()).hexdigest()[:12],
                    timestamp=datetime.now(),
                    rule_id="AI-001",
                    rule_name=f"AI Detected: {ai_result.get('threat_type', 'Unknown')}",
                    category=AttackCategory.ANOMALY,
                    severity=Severity.HIGH if ai_result.get('confidence', 0) > 0.9 else Severity.MEDIUM,
                    source_ip=ip,
                    target=None,
                    raw_log=log_line[:500],
                    confidence=ai_result.get('confidence', 0.5),
                    mitre_technique="AI-ANALYSIS",
                    ai_analysis=ai_result.get('description'),
                    recommended_action=ai_result.get('recommended_action')
                )
                alerts.append(alert)
                self.stats.update(alert)

        # Store and notify
        for alert in alerts:
            self.alerts.append(alert)
            self.alert_queue.put(alert)
            for callback in self.alert_callbacks:
                callback(alert)

        return alerts

    async def tail_file(self, filepath: str):
        """Asynchronously tail a log file."""
        try:
            async with aiofiles.open(filepath, 'r') as f:
                await f.seek(0, 2)  # Seek to end
                while self.running:
                    line = await f.readline()
                    if not line:
                        await asyncio.sleep(0.1)
                        continue
                    line = line.strip()
                    if line:
                        await self.analyze_line(line)
        except Exception as e:
            logger.error(f"Error tailing file {filepath}: {e}")

    async def start(self, log_files: List[str]):
        """Start monitoring provided log files."""
        self.running = True
        await self.ai_analyzer.initialize()
        tasks = [self.tail_file(f) for f in log_files if os.path.exists(f)]
        if tasks:
            await asyncio.gather(*tasks)

    def stop(self):
        """Stop the analyzer gracefully."""
        self.running = False
        asyncio.create_task(self.ai_analyzer.close())
