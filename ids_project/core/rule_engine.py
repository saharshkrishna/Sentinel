from config.settings import FAILED_LOGIN_THRESHOLD, FAILED_LOGIN_WINDOW_SECONDS
from collections import defaultdict
import time
import logging
import re

logger = logging.getLogger("IDS_RuleEngine")

# ─────────────────────────────────────────────────────────────
# Stateful Tracking Stores
# ─────────────────────────────────────────────────────────────

# Auth brute-force sliding window
failed_logins = defaultdict(list)

# Frequency/Flood tracking logic
event_history = defaultdict(list)
FLOOD_THRESHOLD = 20
FLOOD_WINDOW = 10  # seconds

# Account enumeration burst tracking
enum_commands = defaultdict(list)
ENUM_THRESHOLD = 5
ENUM_WINDOW = 30  # seconds

# ─────────────────────────────────────────────────────────────
# Event ID Severity Classification
# Based on MITRE ATT&CK, NIST 800-53, and Microsoft Threat Modeling
# ─────────────────────────────────────────────────────────────

HIGH_EVENTS = {
    4625,   # Failed logon (brute force when repeated)
    4648,   # Logon using explicit credentials (pass-the-hash / runas)
    4720,   # User account created
    4728,   # Member added to security-enabled global group
    4697,   # Service installed on the system (T1543.003 persistence)
    4698,   # Scheduled task created (T1053.005 persistence)
    4732,   # Member added to local Administrators group (T1098)
    4756,   # Member added to universal security-enabled group
    7045,   # New service installed (System log)
    1102,   # Audit log cleared (T1070.001 anti-forensics)
    9999,   # Internal Sentinel alert
}

MEDIUM_EVENTS = {
    4657,   # Registry value modified (T1112)
    4663,   # Object access attempt (file / directory tampering)
    4672,   # Special privileges assigned to new logon (T1078)
    4688,   # New process created (process auditing)
    4702,   # Scheduled task updated
    4768,   # Kerberos TGT requested (T1558.003 Kerberoasting recon)
    4769,   # Kerberos service ticket requested
    4771,   # Kerberos pre-authentication failed
    4776,   # NTLM credential validation attempt (T1110)
    1116,   # Windows Defender: Malware detected
    7000,   # Service failed to start
    7009,   # Service timeout on start
    11707,  # Product installation succeeded (MSI)
    1033,   # Windows Installer transaction
    17,     # Sysmon: Pipe event created
}

LOW_EVENTS = {
    1117,   # Windows Defender: Action taken on malware
    4798,   # User's local group membership enumerated (T1069)
    5156,   # Windows Filtering Platform: connection allowed
    5157,   # Windows Filtering Platform: connection blocked
    10016,  # DCOM permission error
    1014,   # DNS Client: name resolution timeout
    4104,   # PowerShell script block logging
    78,     # Windows Error Reporting
}

# ─────────────────────────────────────────────────────────────
# Pattern-Based Detection Signatures
# Organized by MITRE ATT&CK Tactic / Category
# ─────────────────────────────────────────────────────────────

# --- Suspicious execution paths (Initial Access / Execution) ---
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\appdata\\(?:local|roaming)", re.I),
    re.compile(r"\\temp\\", re.I),
    re.compile(r"\\windows\\temp\\", re.I),
    re.compile(r"/tmp/", re.I),
    re.compile(r"/dev/shm/", re.I),
    re.compile(r"/var/tmp/", re.I),
]

# --- PowerShell obfuscation and abuse (T1059.001 / T1027) ---
POWERSHELL_ABUSE_PATTERNS = [
    re.compile(r"(?:powershell|pwsh).*-(?:enc(?:oded)?(?:c(?:ommand)?)?)\s+[A-Za-z0-9+/=]{20,}", re.I),
    re.compile(r"(?:powershell|pwsh).*-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)", re.I),
    re.compile(r"(?:IEX|Invoke-Expression)\s*\(", re.I),
    re.compile(r"(?:Invoke-WebRequest|iwr|wget|curl)\s+.*\|\s*(?:IEX|Invoke-Expression)", re.I),
    re.compile(r"New-Object\s+(?:Net\.WebClient|IO\.StreamReader)", re.I),
    re.compile(r"\.DownloadString\s*\(", re.I),
    re.compile(r"\.DownloadFile\s*\(", re.I),
    re.compile(r"\[Convert\]::FromBase64String", re.I),
    re.compile(r"-w(?:indowstyle)?\s+hidden", re.I),
    re.compile(r"(?:Set-MpPreference|Add-MpPreference).*-(?:Exclusion|DisableRealtimeMonitoring)", re.I),
]

# --- Credential dumping / theft tool signatures (T1003) ---
CREDENTIAL_DUMP_PATTERNS = [
    re.compile(r"mimikatz", re.I),
    re.compile(r"sekurlsa", re.I),
    re.compile(r"procdump.*-ma\s+lsass", re.I),
    re.compile(r"comsvcs\.dll.*MiniDump", re.I),
    re.compile(r"ntdsutil.*(?:ifm|\"activate instance ntds\")", re.I),
    re.compile(r"(?:reg\s+save|reg\.exe\s+save)\s+(?:hklm\\sam|hklm\\security|hklm\\system)", re.I),
    re.compile(r"(?:gsecdump|wce\b|lazagne|pypykatz|crackmapexec)", re.I),
    re.compile(r"(?:hashcat|john)\s+", re.I),
]

# --- Ransomware behavioral indicators (T1486) ---
RANSOMWARE_PATTERNS = [
    re.compile(r"\.(?:encrypted|locked|crypt|crypted|enc|pay2key|locky|cerber|wannacry|ryuk|dharma|phobos)\b", re.I),
    re.compile(r"readme.*(?:ransom|decrypt|restore|recover|payment)", re.I),
    re.compile(r"your.files.*(?:encrypted|locked)", re.I),
    re.compile(r"bitcoin.*(?:wallet|payment|address)", re.I),
]

# --- WMI abuse (T1047 lateral movement / persistence) ---
WMI_ABUSE_PATTERNS = [
    re.compile(r"wmic(?:\.exe)?\s+(?:process\s+call\s+create|os\s+get)", re.I),
    re.compile(r"wmic(?:\.exe)?\s+/node:", re.I),
    re.compile(r"Invoke-WmiMethod", re.I),
    re.compile(r"Set-WmiInstance", re.I),
]

# --- DLL sideloading / injection (T1574.002 / T1218) ---
DLL_SIDELOAD_PATTERNS = [
    re.compile(r"rundll32(?:\.exe)?\s+(?!shell32|url\.dll|dfshim|iesetup|setupapi|shdocvw|advpack)", re.I),
    re.compile(r"regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:", re.I),
    re.compile(r"(?:mshta|mshta\.exe)\s+(?:javascript:|vbscript:|http)", re.I),
    re.compile(r"mavinject(?:\.exe)?\s+\d+\s+/INJECTRUNNING", re.I),
]

# --- SSH key injection / lateral movement (T1098.004) ---
SSH_TAMPER_PATTERNS = [
    re.compile(r"(?:>>|>)\s*~?/?\.ssh/authorized_keys", re.I),
    re.compile(r"echo\s+.*ssh-(?:rsa|ed25519|ecdsa).*>>?\s*.*authorized_keys", re.I),
    re.compile(r"ssh-keygen\s+-t.*-f\s+/(?:tmp|dev/shm)", re.I),
]

# --- Kernel module loading / rootkit indicators (T1014 / T1547.006) ---
KERNEL_MODULE_PATTERNS = [
    re.compile(r"\b(?:insmod|modprobe)\s+(?!/lib/modules)", re.I),
    re.compile(r"\brmmod\s+", re.I),
    re.compile(r"echo\s+.*>\s*/proc/sys/", re.I),
    re.compile(r"sysctl\s+-w\s+", re.I),
]

# --- Firewall and security tool tampering (T1562) ---
FIREWALL_TAMPER_PATTERNS = [
    re.compile(r"iptables\s+(?:-F|-X|--flush|--delete-chain)", re.I),
    re.compile(r"nft\s+(?:flush|delete)\s+", re.I),
    re.compile(r"ufw\s+(?:disable|reset)", re.I),
    re.compile(r"firewall-cmd\s+.*--remove", re.I),
    re.compile(r"setenforce\s+0", re.I),
    re.compile(r"netsh\s+advfirewall\s+set\s+.*state\s+off", re.I),
    re.compile(r"(?:Set-MpPreference|sc\.exe)\s+.*(?:disable|stop).*(?:defender|windefend|mpssvc)", re.I),
    re.compile(r"net\s+stop\s+(?:windefend|mpssvc|wscsvc|SecurityHealthService)", re.I),
]

# --- Linux privilege escalation (T1548) ---
LINUX_PRIVESC_PATTERNS = [
    re.compile(r"(?:sudo\s+su\b|sudo\s+-i\b|sudo\s+bash\b|sudo\s+/bin/sh)", re.I),
    re.compile(r"chmod\s+[0-7]*s[0-7]*\s+", re.I),
    re.compile(r"chmod\s+(?:4755|4775|4777|2755|6755)\s+", re.I),
    re.compile(r"(?:find\s+/\s+.*-perm\s+.*4000|find\s+/\s+.*-perm\s+.*-u=s)", re.I),
    re.compile(r"(?:linpeas|linenum|linux-exploit-suggester|pspy)", re.I),
]

# --- Crontab / scheduled job persistence (T1053.003) ---
CRON_TAMPER_PATTERNS = [
    re.compile(r"crontab\s+-(?:e|r|l)", re.I),
    re.compile(r"(?:>>|>)\s*/etc/cron", re.I),
    re.compile(r"(?:>>|>)\s*/var/spool/cron", re.I),
    re.compile(r"at\s+-f\s+.*\.sh", re.I),
    re.compile(r"systemctl\s+(?:enable|start)\s+.*timer", re.I),
]

# --- User and group manipulation (T1136 / T1098) ---
USER_MANIPULATION_PATTERNS = [
    re.compile(r"\b(?:useradd|adduser)\s+", re.I),
    re.compile(r"\b(?:usermod)\s+.*(?:-aG|-G)\s+(?:sudo|wheel|admin|root)", re.I),
    re.compile(r"\b(?:net\s+user|net\.exe\s+user)\s+.*\/add", re.I),
    re.compile(r"\b(?:net\s+localgroup|net\.exe\s+localgroup)\s+.*(?:admin|Remote Desktop).*\/add", re.I),
    re.compile(r"\bpasswd\s+-d\s+", re.I),
]

# --- Systemd persistence (T1543.002) ---
SYSTEMD_PERSISTENCE_PATTERNS = [
    re.compile(r"(?:>>|>|cp|mv|ln)\s+.*(?:/etc/systemd/system/|/usr/lib/systemd/system/).*\.(?:service|timer)", re.I),
    re.compile(r"systemctl\s+(?:enable|daemon-reload)", re.I),
]

# --- Data exfiltration / staging (T1560 / T1041) ---
DATA_STAGING_PATTERNS = [
    re.compile(r"(?:tar|7z|zip|rar)\s+.*(?:/home|/etc|/var|C:\\Users|Documents|Desktop)", re.I),
    re.compile(r"(?:scp|rsync|rclone)\s+.*(?:/home|/etc|/var|C:\\Users)", re.I),
    re.compile(r"curl\s+.*(?:-T|--upload-file|-d\s+@|-F\s+file=)", re.I),
    re.compile(r"(?:mega-put|mega-cmd|rclone\s+copy)", re.I),
]

# --- DNS exfiltration indicators (T1071.004) ---
DNS_EXFIL_PATTERNS = [
    re.compile(r"(?:nslookup|dig|host)\s+[a-zA-Z0-9]{30,}\.", re.I),
    re.compile(r"\.(?:dnscat|iodine|dns2tcp)\.", re.I),
    re.compile(r"txt\s+.*[a-zA-Z0-9+/=]{50,}", re.I),
]

# --- Account / domain enumeration (T1087 / T1069) ---
ENUMERATION_PATTERNS = [
    re.compile(r"\bnet\s+(?:user|group|localgroup|accounts|view|share|session|use)\b", re.I),
    re.compile(r"\bwhoami\s+/(?:all|priv|groups)", re.I),
    re.compile(r"\bnltest\s+/(?:dclist|domain_trusts|dsgetdc)", re.I),
    re.compile(r"\bdsquery\s+", re.I),
    re.compile(r"\bldapsearch\s+", re.I),
    re.compile(r"(?:bloodhound|sharphound)", re.I),
    re.compile(r"\bnmap\s+", re.I),
    re.compile(r"\benum4linux", re.I),
    re.compile(r"\bcat\s+/etc/(?:passwd|shadow|group)", re.I),
    re.compile(r"\bgetent\s+(?:passwd|group|shadow)", re.I),
]

# ─────────────────────────────────────────────────────────────
# Prioritized Pattern Rule Sets
# ─────────────────────────────────────────────────────────────

# Each tuple: (pattern_list, severity, rule_label)
HIGH_PATTERN_RULES = [
    (CREDENTIAL_DUMP_PATTERNS,    "HIGH",   "Credential_Dumping_Tool"),
    (POWERSHELL_ABUSE_PATTERNS,   "HIGH",   "PowerShell_Obfuscation_Abuse"),
    (RANSOMWARE_PATTERNS,         "HIGH",   "Ransomware_Behavioral_Indicator"),
    (WMI_ABUSE_PATTERNS,          "HIGH",   "WMI_Lateral_Movement"),
    (DLL_SIDELOAD_PATTERNS,       "HIGH",   "DLL_Sideload_Injection"),
    (SSH_TAMPER_PATTERNS,         "HIGH",   "SSH_Key_Injection"),
    (KERNEL_MODULE_PATTERNS,      "HIGH",   "Kernel_Module_Tampering"),
    (FIREWALL_TAMPER_PATTERNS,    "HIGH",   "Security_Tool_Tampering"),
]

MEDIUM_PATTERN_RULES = [
    (LINUX_PRIVESC_PATTERNS,       "MEDIUM", "Linux_Privilege_Escalation"),
    (USER_MANIPULATION_PATTERNS,   "MEDIUM", "User_Account_Manipulation"),
    (CRON_TAMPER_PATTERNS,         "MEDIUM", "Scheduled_Job_Tampering"),
    (SYSTEMD_PERSISTENCE_PATTERNS, "MEDIUM", "Systemd_Persistence"),
    (DATA_STAGING_PATTERNS,        "MEDIUM", "Data_Staging_Exfiltration"),
    (DNS_EXFIL_PATTERNS,           "MEDIUM", "DNS_Exfiltration_Indicator"),
]


def evaluate_event(event_data):
    """
    Evaluates an event using professional rule-based heuristics.
    Returns categorized severity: "HIGH", "HIGH_FLOOD", "MEDIUM", "LOW", or "NORMAL"
    """
    if event_data.get('source') == 'CanarySentry':
        return "HIGH"

    # LotL Process Lineage Check
    if event_data.get('lotl_rule'):
        logger.warning(f"Rule Engine: LotL Threat Flagged: {event_data['lotl_rule']}")
        return event_data.get('lotl_severity', 'HIGH')

    event_id = event_data.get('event_id')
    message = event_data.get('message', '').lower()
    cmdline = event_data.get('cmdline', '').lower()
    combined_text = f"{message} {cmdline}".strip()
    user = event_data.get('user', 'Unknown')
    current_time = time.time()
    
    # 0. Global Sliding-Window Frequency Matching
    if event_id:
        key = f"{event_id}_{user}"
        event_history[key] = [t for t in event_history[key] if current_time - t <= FLOOD_WINDOW]
        event_history[key].append(current_time)
        
        if len(event_history[key]) >= FLOOD_THRESHOLD:
            logger.warning(f"Rule Engine: FLOOD DETECTED for Event {event_id}.")
            return "HIGH_FLOOD"
    
    # 1. Suspicious Path Execution (Windows + Linux)
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(combined_text):
            logger.warning(f"Rule Engine: Suspicious path execution detected.")
            return "HIGH"

    # 2. HIGH Severity Pattern-Based Rules
    for patterns, severity, rule_label in HIGH_PATTERN_RULES:
        for pat in patterns:
            if pat.search(combined_text):
                logger.warning(f"Rule Engine: {rule_label} detected | User: {user}")
                return severity

    # 3. MEDIUM Severity Pattern-Based Rules
    for patterns, severity, rule_label in MEDIUM_PATTERN_RULES:
        for pat in patterns:
            if pat.search(combined_text):
                logger.info(f"Rule Engine: {rule_label} detected | User: {user}")
                return severity

    # 4. Account Enumeration Rapid-Fire Detection (escalates to HIGH on burst)
    for pat in ENUMERATION_PATTERNS:
        if pat.search(combined_text):
            key = f"enum_{user}"
            enum_commands[key] = [t for t in enum_commands[key] if current_time - t <= ENUM_WINDOW]
            enum_commands[key].append(current_time)
            if len(enum_commands[key]) >= ENUM_THRESHOLD:
                logger.warning(f"Rule Engine: Rapid enumeration burst from user '{user}'.")
                return "HIGH"
            return "LOW"

    # 5. Offline / Raw Text / Linux Auth Log Fallbacks
    if event_id is None or event_id == 0:
        is_auth_failure = (
            "failed login" in message
            or "unauthorized" in message
            or "failed password" in message
            or "authentication failure" in message
            or "invalid user" in message
            or "not in sudoers" in message
        )
        if is_auth_failure:
            failed_logins[user] = [t for t in failed_logins[user] if current_time - t <= FAILED_LOGIN_WINDOW_SECONDS]
            failed_logins[user].append(current_time)
            if len(failed_logins[user]) >= FAILED_LOGIN_THRESHOLD:
                logger.warning(f"Rule Engine: Brute force detected for user '{user}'.")
                return "HIGH"
            return "MEDIUM"

        if "error" in message or "exception" in message or "denied" in message:
            return "LOW"
        return "NORMAL"
        
    # 6. Explicit Event ID Rules
    if event_id in HIGH_EVENTS:
        if event_id == 4625: # Failed login brute force logic
            failed_logins[user] = [t for t in failed_logins[user] if current_time - t <= FAILED_LOGIN_WINDOW_SECONDS]
            failed_logins[user].append(current_time)
            
            if len(failed_logins[user]) >= FAILED_LOGIN_THRESHOLD:
                logger.warning(f"Rule Engine: Brute force detected for {user}.")
                return "HIGH"
            return "MEDIUM" # Single failure is medium severity
        return "HIGH"
        
    if event_id in MEDIUM_EVENTS:
        return "MEDIUM"
        
    if event_id in LOW_EVENTS:
        return "LOW"
        
    # Ignore / noise filtering
    return "NORMAL"
