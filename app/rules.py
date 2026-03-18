"""
rules.py - MITRE ATT&CK based detection rules database.
"""

import re
from app.models import DetectionRule, AttackCategory, Severity

RULES_DATABASE = [
    # T1110 - Brute Force
    DetectionRule(
        id="RULE-001",
        name="Multiple Failed Login Attempts",
        category=AttackCategory.CREDENTIAL_ACCESS,
        mitre_id="T1110",
        pattern=re.compile(r'(?i)(failed|invalid|authentication failure).*(password|login|auth).*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects brute force or password spraying attacks"
    ),

    # T1059.001 - PowerShell Abuse
    DetectionRule(
        id="RULE-002",
        name="Suspicious PowerShell Execution",
        category=AttackCategory.EXECUTION,
        mitre_id="T1059.001",
        pattern=re.compile(r'(?i)(powershell\.exe|pwsh).*(-enc|-encodedcommand|-nop|-noprofile|-windowstyle hidden|bypass|iex|invoke-expression)', re.IGNORECASE),
        severity=Severity.CRITICAL,
        description="Detects obfuscated or suspicious PowerShell execution"
    ),

    # T1003 - Credential Dumping
    DetectionRule(
        id="RULE-003",
        name="Credential Dumping Attempt",
        category=AttackCategory.CREDENTIAL_ACCESS,
        mitre_id="T1003",
        pattern=re.compile(r'(?i)(lsass\.exe|sam|security|system).*(\bdump\b|\bdumping\b|mimikatz|sekurlsa|comsvcs\.dll)', re.IGNORECASE),
        severity=Severity.CRITICAL,
        description="Detects attempts to dump credentials from memory or SAM database"
    ),

    # T1090 - Proxy Tunneling
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

    # T1190 - Web Exploitation
    DetectionRule(
        id="RULE-007",
        name="Web Exploitation Attempt",
        category=AttackCategory.INITIAL_ACCESS,
        mitre_id="T1190",
        pattern=re.compile(r'(?i)(sqlmap|nikto|nmap|masscan|\.env|config\.xml|web\.config|/etc/passwd|../|select.*from|union.*select)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects scanning or exploitation attempts against web applications"
    ),

    # T1053 - Scheduled Task
    DetectionRule(
        id="RULE-008",
        name="Suspicious Scheduled Task Creation",
        category=AttackCategory.PERSISTENCE,
        mitre_id="T1053",
        pattern=re.compile(r'(?i)(schtasks|at\.exe|cron).*(\\.exe|\\.ps1|\\.bat|\\.vbs|powershell|cmd\.exe|/create|/run)', re.IGNORECASE),
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

    # T1071.004 - DNS Tunneling
    DetectionRule(
        id="RULE-010",
        name="DNS Tunneling Suspected",
        category=AttackCategory.C2,
        mitre_id="T1071.004",
        pattern=re.compile(r'(?i)([a-z0-9]{30,}\.[a-z]{2,}|dns.*query.*(txt|mx|aaaa).*[a-z0-9]{20,})', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects potential DNS tunneling via long subdomain queries"
    ),

    # T1083 - File Discovery
    DetectionRule(
        id="RULE-011",
        name="Reconnaissance Activity",
        category=AttackCategory.DISCOVERY,
        mitre_id="T1083",
        pattern=re.compile(r'(?i)(dir.*\/s|ls -la|find.*-name|tree.*\/f|cmd.*\/c.*dir|get-childitem)', re.IGNORECASE),
        severity=Severity.LOW,
        description="Detects file system enumeration activities"
    ),

    # T1047 - WMI Abuse
    DetectionRule(
        id="RULE-012",
        name="WMI Abuse Detected",
        category=AttackCategory.EXECUTION,
        mitre_id="T1047",
        pattern=re.compile(r'(?i)(wmic.*process.*call create|wmiexec|win32_process|Invoke-WmiMethod)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects WMI being used for command execution"
    ),

    # T1021 - Remote Brute Force
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

    # T1496 - Cryptomining
    DetectionRule(
        id="RULE-015",
        name="Cryptomining Activity",
        category=AttackCategory.IMPACT,
        mitre_id="T1496",
        pattern=re.compile(r'(?i)(xmrig|minerd|stratum\+tcp|nanopool|minexmr|cryptonight|hashrate)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects cryptocurrency mining activity"
    ),

    # T1059.003 - CMD Abuse
    DetectionRule(
        id="RULE-016",
        name="Suspicious CMD Execution",
        category=AttackCategory.EXECUTION,
        mitre_id="T1059.003",
        pattern=re.compile(r'(?i)(cmd\.exe.*\/c.*powershell|cmd\.exe.*\/c.*certutil|cmd\.exe.*\/c.*bitsadmin|cmd\.exe.*&&.*del)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects suspicious command prompt usage"
    ),

    # T1543 - Service Creation
    DetectionRule(
        id="RULE-017",
        name="Suspicious Service Creation",
        category=AttackCategory.PERSISTENCE,
        mitre_id="T1543",
        pattern=re.compile(r'(?i)(sc\.exe.*create|new-service|installutil.*\/logfile=|regsvr32.*\/s)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects creation of suspicious system services"
    ),

    # T1218 - LOLBins Abuse
    DetectionRule(
        id="RULE-018",
        name="LOLBins Abuse",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1218",
        pattern=re.compile(r'(?i)(rundll32\.exe.*javascript|regsvr32.*\/i|mshta.*http|certutil.*-decode|cscript.*\.wsf)', re.IGNORECASE),
        severity=Severity.HIGH,
        description="Detects Living Off The Land binary abuse"
    ),

    # T1001 - Data Obfuscation
    DetectionRule(
        id="RULE-019",
        name="Data Obfuscation Detected",
        category=AttackCategory.C2,
        mitre_id="T1001",
        pattern=re.compile(r'(?i)(base64.*decode|frombase64string| -enc [a-zA-Z0-9+/]{100,}|powershell.*[a-zA-Z0-9+/]{100,})', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects use of encoding to obfuscate commands"
    ),

    # T1497 - Sandbox Evasion
    DetectionRule(
        id="RULE-020",
        name="Sandbox Evasion Technique",
        category=AttackCategory.DEFENSE_EVASION,
        mitre_id="T1497",
        pattern=re.compile(r'(?i)(vmware|virtualbox|sandboxie|cuckoo|qemu|xen).*detect|check.*debug|IsDebuggerPresent', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Detects malware checking for virtualized environments"
    ),
]
