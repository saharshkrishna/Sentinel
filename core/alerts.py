"""
alerts.py - Core data models for alerts, severities, and threat statistics tracking.
"""

import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AttackCategory(Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    C2 = "Command and Control"
    IMPACT = "Impact"
    ANOMALY = "AI Detected Anomaly"

@dataclass
class Alert:
    id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    category: AttackCategory
    severity: Severity
    source_ip: Optional[str]
    target: Optional[str]
    raw_log: str
    confidence: float
    mitre_technique: str
    ai_analysis: Optional[str] = None
    recommended_action: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

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
