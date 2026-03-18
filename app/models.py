"""
models.py - Core data models: enums and dataclasses used across the application.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any
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
class DetectionRule:
    id: str
    name: str
    category: AttackCategory
    mitre_id: str
    pattern: re.Pattern
    severity: Severity
    description: str
    false_positive_rate: float = 0.1
    enabled: bool = True


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
