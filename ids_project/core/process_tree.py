"""
process_tree.py - Process Lineage Directed Acyclic Graph (DAG) & Living-off-the-Land (LotL) Engine.
Maintains parent-to-child relationships, command-line arguments, execution lineage,
and evaluates behavioral process tree heuristics to catch advanced malware chains.
"""
import os
import sys
import time
import re
import logging
import threading
from typing import NamedTuple
import psutil

from core.platform_adapter import IS_WINDOWS, IS_LINUX

logger = logging.getLogger("IDS_ProcessTree")


class ProcessNode:
    """Represents a process node within the execution lineage DAG."""
    def __init__(self, pid: int, ppid: int, name: str, cmdline: str = "",
                 exe_path: str = "N/A", user: str = "Unknown", start_time: float = 0.0):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = cmdline
        self.exe_path = exe_path
        self.user = user
        self.start_time = start_time or time.time()
        self.children: set[int] = set()

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline,
            "exe_path": self.exe_path,
            "user": self.user,
            "start_time": self.start_time,
            "children": list(self.children)
        }


# ─────────────────────────────────────────────────────────────
# Living-off-the-Land (LotL) Behavioral Detection Signatures
# ─────────────────────────────────────────────────────────────

# Windows LotL Parent-Child & CLI Rules
WIN_OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "msaccess.exe"
}
WIN_DANGEROUS_CHILDREN = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "vssadmin.exe",
    "rundll32.exe", "regsvr32.exe", "wmic.exe"
}

# Linux LotL Parent-Child & CLI Rules
LINUX_WEBSERVER_PARENTS = {
    "nginx", "httpd", "apache2", "node", "php-fpm", "tomcat",
    "mongod", "redis-server", "gunicorn", "uwsgi"
}
LINUX_DANGEROUS_CHILDREN = {
    "sh", "bash", "dash", "zsh", "python", "python3", "perl",
    "nc", "ncat", "netcat", "curl", "wget"
}

REVERSE_SHELL_PATTERNS = [
    re.compile(r"nc(?:at)?\s+(?:-[a-zA-Z]*e|--exec)\s+(?:/bin/)?(?:ba)?sh", re.I),
    re.compile(r"(?:/bin/)?(?:ba)?sh\s+-i\s+>&?\s*/dev/tcp/", re.I),
    re.compile(r"python(?:3)?\s+-c\s+['\"].*import\s+(?:pty|socket|subprocess).*['\"]", re.I),
    re.compile(r"(?:curl|wget)\s+.*\|\s*(?:ba)?sh", re.I),
    re.compile(r"mkfifo\s+/tmp/.*(?:ba)?sh", re.I)
]

SHADOW_TAMPER_PATTERNS = [
    re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.I),
    re.compile(r"wbadmin(?:\.exe)?\s+delete\s+catalog", re.I),
    re.compile(r"wmic(?:\.exe)?\s+shadowcopy\s+delete", re.I),
    re.compile(r"bcdedit(?:\.exe)?\s+/set\s+.*recoveryenabled\s+no", re.I)
]

CERTUTIL_DOWNLOAD_PATTERNS = [
    re.compile(r"certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9]*urlcache|-split|-f)", re.I),
    re.compile(r"bitsadmin(?:\.exe)?\s+/transfer", re.I)
]

# Windows: PowerShell from suspicious/uncommon parents (T1059.001)
POWERSHELL_SUSPICIOUS_PARENTS = {
    "wmiprvse.exe", "w3wp.exe", "sqlservr.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "cmstp.exe", "certutil.exe",
    "dllhost.exe", "wscript.exe", "cscript.exe"
}

# Windows: Process hollowing — benign system names from non-standard parents (T1055.012)
HOLLOWING_TARGETS = {
    "svchost.exe", "dllhost.exe", "taskhost.exe", "lsass.exe",
    "services.exe", "smss.exe", "conhost.exe", "RuntimeBroker.exe"
}
HOLLOWING_LEGIT_PARENTS = {
    "services.exe", "wininit.exe", "smss.exe", "svchost.exe",
    "lsass.exe", "winlogon.exe"
}

# Linux: Cron / at daemon parent set
LINUX_CRON_PARENTS = {"cron", "crond", "atd", "anacron"}

# Scripting engines that should rarely spawn network tools
SCRIPT_ENGINES = {
    "python", "python3", "perl", "ruby", "node", "php",
    "wscript.exe", "cscript.exe", "java"
}
NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp",
    "ftp", "tftp", "socat"
}

# Database processes — shell spawning indicates SQL injection (T1190)
DB_PROCESSES = {"mysqld", "postgres", "sqlservr.exe", "mongod", "oracle", "mariadbd"}


class ProcessTree:
    """Thread-safe Process Lineage DAG and LotL behavioral evaluator."""
    def __init__(self):
        self._lock = threading.RLock()
        self._nodes: dict[int, ProcessNode] = {}
        self.running = False
        self._watcher_thread: threading.Thread | None = None

    def add_or_update(self, pid: int, ppid: int, name: str, cmdline: str = "",
                      exe_path: str = "N/A", user: str = "Unknown",
                      start_time: float = 0.0) -> ProcessNode:
        """Add a process node or update its parameters in the DAG."""
        with self._lock:
            node = self._nodes.get(pid)
            if not node:
                node = ProcessNode(pid, ppid, name, cmdline, exe_path, user, start_time)
                self._nodes[pid] = node
            else:
                node.ppid = ppid
                node.name = name or node.name
                if cmdline: node.cmdline = cmdline
                if exe_path and exe_path != "N/A": node.exe_path = exe_path
                if user and user != "Unknown": node.user = user

            # Link with parent if exists
            if ppid in self._nodes and ppid != pid:
                self._nodes[ppid].children.add(pid)

            return node

    def get_node(self, pid: int) -> ProcessNode | None:
        """Fetch a process node by PID."""
        with self._lock:
            return self._nodes.get(pid)

    def get_parent(self, pid: int) -> ProcessNode | None:
        """Fetch immediate parent process node."""
        with self._lock:
            node = self._nodes.get(pid)
            if node and node.ppid and node.ppid in self._nodes:
                return self._nodes[node.ppid]
            return None

    def get_lineage(self, pid: int, max_depth: int = 6) -> list[ProcessNode]:
        """
        Return the ancestor chain from root down to target PID:
        [root, ..., grandparent, parent, target]
        """
        with self._lock:
            chain = []
            curr_pid = pid
            visited = set()

            while curr_pid and curr_pid not in visited and len(chain) < max_depth:
                visited.add(curr_pid)
                node = self._nodes.get(curr_pid)
                if not node:
                    break
                chain.append(node)
                if node.ppid == curr_pid or node.ppid <= 0:
                    break
                curr_pid = node.ppid

            return list(reversed(chain))

    def format_lineage_str(self, pid: int) -> str:
        """Return human-readable ancestor execution chain, e.g., 'systemd (1) -> nginx (842) -> bash (2940)'."""
        chain = self.get_lineage(pid)
        if not chain:
            return "N/A"
        return " -> ".join([f"{n.name} ({n.pid})" for n in chain])

    # ─────────────────────────────────────────────────────────
    # Living-off-the-Land (LotL) Rule Evaluator
    # ─────────────────────────────────────────────────────────
    def evaluate_node(self, node: ProcessNode) -> tuple[bool, str, str]:
        """
        Evaluates a ProcessNode against LotL behavioral attack rules.
        Returns (is_suspicious: bool, severity: str, rule_name: str)
        """
        name_lower = node.name.lower()
        cmd_lower = node.cmdline.lower() if node.cmdline else ""
        parent = self.get_parent(node.pid)
        pname_lower = parent.name.lower() if parent else ""

        # 1. Windows: Office Macro Spawning Command Interpreter
        if pname_lower in WIN_OFFICE_PARENTS and name_lower in WIN_DANGEROUS_CHILDREN:
            return True, "HIGH", f"Windows_Office_Macro_Dropper ({parent.name} -> {node.name})"

        # 2. Windows: Ransomware Volume Shadow Copy & Backup Deletion
        for pat in SHADOW_TAMPER_PATTERNS:
            if pat.search(cmd_lower):
                return True, "HIGH", f"Windows_Ransomware_Shadow_Wipe ({node.name}: {node.cmdline[:60]})"

        # 3. Windows: Certutil / Bitsadmin Malicious Dropper
        for pat in CERTUTIL_DOWNLOAD_PATTERNS:
            if pat.search(cmd_lower):
                return True, "HIGH", f"Windows_LotL_Certutil_Dropper ({node.cmdline[:60]})"

        # 4. Linux: Web Server Spawning Shell (WebShell Execution)
        if pname_lower in LINUX_WEBSERVER_PARENTS and name_lower in LINUX_DANGEROUS_CHILDREN:
            return True, "HIGH", f"Linux_WebShell_Execution ({parent.name} -> {node.name})"

        # 5. Linux: Reverse Shell / Pipe-to-Shell Payload
        for pat in REVERSE_SHELL_PATTERNS:
            if pat.search(cmd_lower):
                return True, "HIGH", f"Linux_Reverse_Shell_Pipeline ({node.cmdline[:60]})"

        # 6. Windows: PowerShell spawned from suspicious parent (WMI, IIS, COM)
        if name_lower in {"powershell.exe", "pwsh.exe"} and pname_lower in POWERSHELL_SUSPICIOUS_PARENTS:
            return True, "HIGH", f"Windows_Suspicious_PowerShell_Parent ({parent.name} -> {node.name})"

        # 7. Windows: Process Hollowing Indicator (system process from wrong parent)
        if name_lower in HOLLOWING_TARGETS and pname_lower and pname_lower not in HOLLOWING_LEGIT_PARENTS:
            return True, "MEDIUM", f"Windows_Process_Hollowing_Indicator ({parent.name} -> {node.name})"

        # 8. Linux: Cron/at daemon spawning interactive shell or downloader
        if pname_lower in LINUX_CRON_PARENTS and name_lower in LINUX_DANGEROUS_CHILDREN:
            return True, "MEDIUM", f"Linux_Cron_Shell_Execution ({parent.name} -> {node.name})"

        # 9. Scripting engine spawning network tool (data exfil / C2 callback)
        if pname_lower in SCRIPT_ENGINES and name_lower in NETWORK_TOOLS:
            return True, "MEDIUM", f"Script_Engine_Network_Access ({parent.name} -> {node.name})"

        # 10. Database process spawning shell (SQL injection indicator)
        if pname_lower in DB_PROCESSES and name_lower in (LINUX_DANGEROUS_CHILDREN | WIN_DANGEROUS_CHILDREN):
            return True, "HIGH", f"Database_Shell_Injection ({parent.name} -> {node.name})"

        return False, "NORMAL", ""

    # ─────────────────────────────────────────────────────────
    # Snapshot & Background Polling Engine
    # ─────────────────────────────────────────────────────────
    def snapshot_running_processes(self):
        """Populate initial process tree from running system processes."""
        count = 0
        attrs = ['pid', 'ppid', 'name', 'cmdline', 'exe', 'username', 'create_time']
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
                cmdline = " ".join(info.get('cmdline') or [])
                self.add_or_update(
                    pid=info['pid'],
                    ppid=info.get('ppid') or 0,
                    name=info.get('name') or "Unknown",
                    cmdline=cmdline,
                    exe_path=info.get('exe') or "N/A",
                    user=info.get('username') or "Unknown",
                    start_time=info.get('create_time') or time.time()
                )
                count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        logger.info(f"ProcessTree baseline initialized with {count} processes.")
        return count

    def prune_stale_nodes(self):
        """Clean up terminated process nodes older than 5 minutes to prevent memory leaks."""
        with self._lock:
            current_time = time.time()
            stale_pids = []
            for pid, node in self._nodes.items():
                if current_time - node.start_time > 300:
                    if not psutil.pid_exists(pid):
                        stale_pids.append(pid)

            for pid in stale_pids:
                del self._nodes[pid]

    def _sync_loop(self):
        """Periodic background sync capturing new processes and pruning stale entries."""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'exe', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        if pid not in self._nodes:
                            cmdline = " ".join(proc.info.get('cmdline') or [])
                            node = self.add_or_update(
                                pid=pid,
                                ppid=proc.info.get('ppid') or 0,
                                name=proc.info.get('name') or "Unknown",
                                cmdline=cmdline,
                                exe_path=proc.info.get('exe') or "N/A",
                                user=proc.info.get('username') or "Unknown",
                                start_time=proc.info.get('create_time') or time.time()
                            )
                            # Evaluate for LotL threats immediately upon creation
                            is_suspicious, sev, rule = self.evaluate_node(node)
                            if is_suspicious:
                                logger.warning(f"LotL Threat Detected by ProcessTree: {rule}")
                                # Dispatch to decision engine so UI, tray, and alerts.json are updated
                                from core.decision_engine import process_event
                                lotl_event = {
                                    "event_id": 0,
                                    "source": node.name,
                                    "event_type": "LotL",
                                    "time_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "message": f"Living-off-the-Land rule triggered: {rule}",
                                    "user": node.user,
                                    "pid": node.pid,
                                    "ppid": node.ppid,
                                    "process_name": node.name,
                                    "exe_path": node.exe_path,
                                    "cmdline": node.cmdline,
                                    "lotl_rule": rule,
                                    "lotl_severity": sev,
                                    "lineage_str": self.format_lineage_str(node.pid),
                                }
                                process_event(lotl_event, silent=False)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self.prune_stale_nodes()
            except Exception as e:
                logger.debug(f"ProcessTree sync loop error: {e}")

            time.sleep(1.0)

    def start(self):
        """Start ProcessTree background synchronization."""
        self.running = True
        self.snapshot_running_processes()
        self._watcher_thread = threading.Thread(target=self._sync_loop, daemon=True, name="ProcessTreeSync")
        self._watcher_thread.start()
        logger.info("ProcessTree synchronization engine started.")

    def stop(self):
        """Stop ProcessTree synchronization."""
        self.running = False


# Singleton instance
_global_tree: ProcessTree | None = None

def get_process_tree() -> ProcessTree:
    """Retrieve or initialize the singleton ProcessTree."""
    global _global_tree
    if _global_tree is None:
        _global_tree = ProcessTree()
    return _global_tree
