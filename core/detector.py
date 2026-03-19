"""
detector.py - Detection rules, AI analyzer, and the main LogAnalyzer orchestrator.
"""

import asyncio
import hashlib
import json
import logging
import os
import queue
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable, List, Optional, Dict
from dataclasses import dataclass

import aiohttp

from core.alerts import Alert, AttackCategory, Severity, StatisticsTracker
from core.log_reader import LogBuffer, tail_file

logger = logging.getLogger(__name__)

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

RULES_DATABASE = [
    DetectionRule(id="RULE-001", name="Multiple Failed Login Attempts", category=AttackCategory.CREDENTIAL_ACCESS, mitre_id="T1110", pattern=re.compile(r'(?i)(failed|invalid|authentication failure).*(password|login|auth).*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE), severity=Severity.HIGH, description="Detects brute force or password spraying attacks"),
    DetectionRule(id="RULE-002", name="Suspicious PowerShell Execution", category=AttackCategory.EXECUTION, mitre_id="T1059.001", pattern=re.compile(r'(?i)(powershell\.exe|pwsh).*(-enc|-encodedcommand|-nop|-noprofile|-windowstyle hidden|bypass|iex|invoke-expression)', re.IGNORECASE), severity=Severity.CRITICAL, description="Detects obfuscated or suspicious PowerShell execution"),
    DetectionRule(id="RULE-003", name="Credential Dumping Attempt", category=AttackCategory.CREDENTIAL_ACCESS, mitre_id="T1003", pattern=re.compile(r'(?i)(lsass\.exe|sam|security|system).*(\bdump\b|\bdumping\b|mimikatz|sekurlsa|comsvcs\.dll)', re.IGNORECASE), severity=Severity.CRITICAL, description="Detects attempts to dump credentials from memory or SAM database"),
    DetectionRule(id="RULE-004", name="Proxy Tunneling Tool Detected", category=AttackCategory.C2, mitre_id="T1090", pattern=re.compile(r'(?i)(ngrok|frpc|frps|pagekite|localtunnel|serveo|localhost\.run)', re.IGNORECASE), severity=Severity.HIGH, description="Detects usage of tunneling/proxy tools for C2 communication"),
    DetectionRule(id="RULE-005", name="Process Injection Activity", category=AttackCategory.DEFENSE_EVASION, mitre_id="T1055", pattern=re.compile(r'(?i)(createRemoteThread|VirtualAllocEx|WriteProcessMemory|NtMapViewOfSection|process.*hollow)', re.IGNORECASE), severity=Severity.HIGH, description="Detects potential process injection techniques"),
    DetectionRule(id="RULE-006", name="Process Masquerading", category=AttackCategory.DEFENSE_EVASION, mitre_id="T1036", pattern=re.compile(r'(?i)(svchost\.exe|lsass\.exe|csrss\.exe|smss\.exe).*(temp\\|appdata\\|programdata\\|users\\public)', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects processes masquerading as system processes from unusual locations"),
    DetectionRule(id="RULE-007", name="Web Exploitation Attempt", category=AttackCategory.INITIAL_ACCESS, mitre_id="T1190", pattern=re.compile(r'(?i)(sqlmap|nikto|nmap|masscan|\.env|config\.xml|web\.config|/etc/passwd|../|select.*from|union.*select)', re.IGNORECASE), severity=Severity.HIGH, description="Detects scanning or exploitation attempts against web applications"),
    DetectionRule(id="RULE-008", name="Suspicious Scheduled Task Creation", category=AttackCategory.PERSISTENCE, mitre_id="T1053", pattern=re.compile(r'(?i)(schtasks|at\.exe|cron).*(\.exe|\.ps1|\.bat|\.vbs|powershell|cmd\.exe|/create|/run)', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects creation of suspicious scheduled tasks for persistence"),
    DetectionRule(id="RULE-009", name="Security Tool Disablement", category=AttackCategory.DEFENSE_EVASION, mitre_id="T1562", pattern=re.compile(r'(?i)(defender|firewall|antivirus|selinux|apparmor).*(disable|stop|off|kill|uninstall|remove)', re.IGNORECASE), severity=Severity.CRITICAL, description="Detects attempts to disable security tools"),
    DetectionRule(id="RULE-010", name="DNS Tunneling Suspected", category=AttackCategory.C2, mitre_id="T1071.004", pattern=re.compile(r'(?i)([a-z0-9]{30,}\.[a-z]{2,}|dns.*query.*(txt|mx|aaaa).*[a-z0-9]{20,})', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects potential DNS tunneling via long subdomain queries"),
    DetectionRule(id="RULE-011", name="Reconnaissance Activity", category=AttackCategory.DISCOVERY, mitre_id="T1083", pattern=re.compile(r'(?i)(dir.*\/s|ls -la|find.*-name|tree.*\/f|cmd.*\/c.*dir|get-childitem)', re.IGNORECASE), severity=Severity.LOW, description="Detects file system enumeration activities"),
    DetectionRule(id="RULE-012", name="WMI Abuse Detected", category=AttackCategory.EXECUTION, mitre_id="T1047", pattern=re.compile(r'(?i)(wmic.*process.*call create|wmiexec|win32_process|Invoke-WmiMethod)', re.IGNORECASE), severity=Severity.HIGH, description="Detects WMI being used for command execution"),
    DetectionRule(id="RULE-013", name="Remote Access Brute Force", category=AttackCategory.LATERAL_MOVEMENT, mitre_id="T1021", pattern=re.compile(r'(?i)(ssh.*failed|rdp.*failed|connection.*closed.*authenticating|invalid user.*from)', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects brute force attempts against remote services"),
    DetectionRule(id="RULE-014", name="Suspicious File Download", category=AttackCategory.C2, mitre_id="T1105", pattern=re.compile(r'(?i)(wget.*http|curl.*http|certutil.*urlcache|bitsadmin.*transfer|downloadstring|invoke-webrequest)', re.IGNORECASE), severity=Severity.HIGH, description="Detects tools being downloaded to the system"),
    DetectionRule(id="RULE-015", name="Cryptomining Activity", category=AttackCategory.IMPACT, mitre_id="T1496", pattern=re.compile(r'(?i)(xmrig|minerd|stratum\+tcp|nanopool|minexmr|cryptonight|hashrate)', re.IGNORECASE), severity=Severity.HIGH, description="Detects cryptocurrency mining activity"),
    DetectionRule(id="RULE-016", name="Suspicious CMD Execution", category=AttackCategory.EXECUTION, mitre_id="T1059.003", pattern=re.compile(r'(?i)(cmd\.exe.*\/c.*powershell|cmd\.exe.*\/c.*certutil|cmd\.exe.*\/c.*bitsadmin|cmd\.exe.*&&.*del)', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects suspicious command prompt usage"),
    DetectionRule(id="RULE-017", name="Suspicious Service Creation", category=AttackCategory.PERSISTENCE, mitre_id="T1543", pattern=re.compile(r'(?i)(sc\.exe.*create|new-service|installutil.*\/logfile=|regsvr32.*\/s)', re.IGNORECASE), severity=Severity.HIGH, description="Detects creation of suspicious system services"),
    DetectionRule(id="RULE-018", name="LOLBins Abuse", category=AttackCategory.DEFENSE_EVASION, mitre_id="T1218", pattern=re.compile(r'(?i)(rundll32\.exe.*javascript|regsvr32.*\/i|mshta.*http|certutil.*-decode|cscript.*\.wsf)', re.IGNORECASE), severity=Severity.HIGH, description="Detects Living Off The Land binary abuse"),
    DetectionRule(id="RULE-019", name="Data Obfuscation Detected", category=AttackCategory.C2, mitre_id="T1001", pattern=re.compile(r'(?i)(base64.*decode|frombase64string| -enc [a-zA-Z0-9+/]{100,}|powershell.*[a-zA-Z0-9+/]{100,})', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects use of encoding to obfuscate commands"),
    DetectionRule(id="RULE-020", name="Sandbox Evasion Technique", category=AttackCategory.DEFENSE_EVASION, mitre_id="T1497", pattern=re.compile(r'(?i)(vmware|virtualbox|sandboxie|cuckoo|qemu|xen).*detect|check.*debug|IsDebuggerPresent', re.IGNORECASE), severity=Severity.MEDIUM, description="Detects malware checking for virtualized environments")
]

class OllamaAnalyzer:
    """AI-powered log analysis using Ollama."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url
        self.model = model
        self.session: Optional[aiohttp.ClientSession] = None
        self.enabled = True
        self.last_call: float = 0.0
        self.rate_limit: float = 1.0

    async def _get_session(self) -> aiohttp.ClientSession:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None

        if self.session is None or self.session.closed or (hasattr(self.session, '_loop') and self.session._loop != loop):
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = aiohttp.ClientSession()
        return self.session

    async def initialize(self):
        await self._get_session()

    async def analyze(self, log_line: str, context: List[Dict]) -> Optional[Dict]:
        session = await self._get_session()
        if not self.enabled or not session:
            return None

        current_time = time.time()
        if current_time - self.last_call < self.rate_limit:
            return None
        self.last_call = current_time

        context_str = "\n".join([f"[{c['timestamp']}] {c['log']}" for c in context[-5:]])
        prompt = f"""You are a cybersecurity expert analyzing system logs for threats.
Analyze the following log entry and recent context for security threats, anomalies, or attack patterns.

Recent Context:
{context_str}

Current Log Entry:
{log_line}

Provide a JSON response with this exact structure:
{{
    "is_threat": boolean,
    "threat_type": "none" | "malware" | "intrusion" | "anomaly" | "reconnaissance" | "data_exfiltration",
    "confidence": 0.0-1.0,
    "description": "brief explanation",
    "recommended_action": "specific remediation step",
    "indicators": ["list", "of", "ioc", "indicators"]
}}

Respond ONLY with the JSON object, no other text."""

        try:
            async with session.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    try:
                        response_text = result.get('response', '')
                        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                        if json_match:
                            return json.loads(json_match.group())
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse AI response as JSON")
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")

        return None

    async def close(self):
        if self.session:
            await self.session.close()

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
        self.suspicious_ips = defaultdict(lambda: {'count': 0, 'first_seen': None, 'alerts': []})

    def register_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)

    def extract_ip(self, log_line: str) -> Optional[str]:
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        return match.group(0) if match else None

    def calculate_confidence(self, rule, log_line: str, ip: Optional[str]) -> float:
        indicators = 0.0
        if re.search(r'(?i)(admin|root|system)', log_line): indicators += 0.1
        if re.search(r'(?i)(error|fail|denied)', log_line): indicators += 0.1
        if ip and self.suspicious_ips[ip]['count'] > 3: indicators += 0.2
        if ip and self.suspicious_ips[ip]['alerts']:
            if (datetime.now() - self.suspicious_ips[ip]['alerts'][-1]).total_seconds() < 300:
                indicators += 0.1
        return min(0.7 + indicators, 1.0)

    async def analyze_line(self, log_line: str) -> List[Alert]:
        alerts: List[Alert] = []
        self.buffer.add(log_line)
        self.stats.increment_logs()

        ip = self.extract_ip(log_line)

        # Rule-based detection
        for rule in self.rules:
            if not rule.enabled: continue
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

        # AI analysis if no hits
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

        for alert in alerts:
            self.alerts.append(alert)
            self.alert_queue.put(alert)
            for callback in self.alert_callbacks:
                callback(alert)

        return alerts

    async def start(self, log_files: List[str]):
        self.running = True
        await self.ai_analyzer.initialize()
        tasks = [tail_file(f, self.analyze_line, lambda: self.running) for f in log_files if os.path.exists(f)]
        if tasks:
            await asyncio.gather(*tasks)

    def stop(self):
        self.running = False
        asyncio.create_task(self.ai_analyzer.close())
