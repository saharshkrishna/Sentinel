"""
stats.py - Thread-safe detection statistics tracker.
"""

import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict

from app.models import Alert


class StatisticsTracker:
    """Track detection statistics."""

    def __init__(self):
        self.stats = {
            'total_logs_processed': 0,
            'alerts_generated': 0,
            'rule_hits': defaultdict(int),
            'severity_counts': defaultdict(int),
            'category_counts': defaultdict(int),
            'timeline': deque(maxlen=100),
            'top_source_ips': defaultdict(int),
            'mitre_coverage': set()
        }
        self.lock = threading.Lock()

    def update(self, alert: Alert):
        with self.lock:
            self.stats['alerts_generated'] += 1
            self.stats['rule_hits'][alert.rule_id] += 1
            self.stats['severity_counts'][alert.severity.value] += 1
            self.stats['category_counts'][alert.category.value] += 1
            self.stats['mitre_coverage'].add(alert.mitre_technique)
            if alert.source_ip:
                self.stats['top_source_ips'][alert.source_ip] += 1
            self.stats['timeline'].append({
                'time': datetime.now().isoformat(),
                'severity': alert.severity.value,
                'category': alert.category.value
            })

    def increment_logs(self):
        with self.lock:
            self.stats['total_logs_processed'] += 1

    def get_stats(self) -> Dict:
        with self.lock:
            return {
                **self.stats,
                'mitre_coverage': list(self.stats['mitre_coverage']),
                'top_source_ips': dict(sorted(
                    self.stats['top_source_ips'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]),
                'rule_hits': dict(self.stats['rule_hits']),
                'severity_counts': dict(self.stats['severity_counts']),
                'category_counts': dict(self.stats['category_counts']),
                'timeline': list(self.stats['timeline'])
            }
