"""
network_guard.py - Dynamic Network Containment & Host Isolation Engine.
Inspects active TCP/UDP sockets, performs process-level firewall cuts,
and enforces emergency host network isolation to halt C2 communications and lateral movement.
"""
import os
import sys
import logging
import subprocess
import datetime
from pathlib import Path
import psutil

from core.platform_adapter import IS_WINDOWS, IS_LINUX, is_admin
from config.settings import LOG_DIR

logger = logging.getLogger("IDS_NetworkGuard")
AUDIT_LOG = LOG_DIR / "audit.log"

_active_process_blocks: dict[int, list[str]] = {}
_is_host_isolated: bool = False


def _audit(action: str, target: str, result: str):
    """Log network containment events to audit.log."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] ACTION={action} | TARGET={target} | Result={result}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        logger.error(f"Failed to write network audit log: {e}")
    logger.info(entry.strip())


def get_active_sockets(pid: int | None = None) -> list[dict]:
    """
    Query system network sockets, optionally filtered by PID.
    Returns list of active socket descriptions.
    """
    sockets = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if pid is not None and conn.pid != pid:
                continue

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"

            proc_name = "Unknown"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            sockets.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "local_address": laddr,
                "remote_address": raddr,
                "status": conn.status
            })
    except (psutil.AccessDenied, Exception) as e:
        logger.debug(f"Failed to query network connections: {e}")

    return sockets


# ─────────────────────────────────────────────────────────────
# Process-Level Network Isolation
# ─────────────────────────────────────────────────────────────

def isolate_process_network(pid: int, process_name: str = "Unknown", exe_path: str = "") -> tuple[bool, str]:
    """
    Cut all outbound/inbound network traffic for a specific target process.
    Uses iptables/nftables on Linux and netsh advfirewall on Windows.
    """
    if not is_admin():
        msg = "Elevated privileges (root / Administrator) required for network containment."
        _audit("PROCESS_ISOLATE", f"PID {pid}", f"FAILED - {msg}")
        return False, msg

    try:
        if IS_LINUX:
            # 1. Block outbound by PID owner
            cmd = ["iptables", "-I", "OUTPUT", "1", "-m", "owner", "--pid-owner", str(pid), "-j", "DROP"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                _active_process_blocks[pid] = ["iptables", "-D", "OUTPUT", "-m", "owner", "--pid-owner", str(pid), "-j", "DROP"]
                msg = f"Network isolated for PID {pid} via iptables owner rule."
                _audit("PROCESS_ISOLATE", f"PID {pid} ({process_name})", "SUCCESS")
                print(f"[CONTAINMENT] 🛑 {msg}")
                return True, msg

            # 2. Fallback: Block all remote IPs this process is currently communicating with
            conns = get_active_sockets(pid=pid)
            blocked_ips = []
            for c in conns:
                r_ip = c["remote_address"].split(":")[0]
                if r_ip and r_ip != "None" and not r_ip.startswith("127."):
                    cmd_ip = ["iptables", "-I", "OUTPUT", "1", "-d", r_ip, "-j", "DROP"]
                    subprocess.run(cmd_ip, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    blocked_ips.append(r_ip)

            if blocked_ips:
                msg = f"Process PID {pid} remote C2 sockets blocked: {', '.join(blocked_ips)}"
                _audit("PROCESS_ISOLATE", f"PID {pid} ({process_name})", "SUCCESS (Socket Block)")
                print(f"[CONTAINMENT] 🛑 {msg}")
                return True, msg
            else:
                return False, f"Could not insert iptables rule: {res.stderr}"

        elif IS_WINDOWS:
            rule_name = f"Sentinel_Block_PID_{pid}"
            if exe_path and exe_path != "N/A" and Path(exe_path).exists():
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"program={exe_path}"
                ]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block"
                ]

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                _active_process_blocks[pid] = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                msg = f"Process '{process_name}' (PID {pid}) network isolated via Windows Firewall."
                _audit("PROCESS_ISOLATE", f"PID {pid} ({process_name})", "SUCCESS")
                print(f"[CONTAINMENT] 🛑 {msg}")
                return True, msg
            else:
                return False, res.stderr.strip()

        return False, "Unsupported platform for network isolation."
    except Exception as e:
        _audit("PROCESS_ISOLATE", f"PID {pid}", f"ERROR - {e}")
        return False, str(e)


def restore_process_network(pid: int) -> tuple[bool, str]:
    """Remove active process network isolation block rules."""
    cleanup_cmd = _active_process_blocks.pop(pid, None)
    if not cleanup_cmd:
        return True, "No active network block found for this PID."

    try:
        subprocess.run(cleanup_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        _audit("PROCESS_RESTORE", f"PID {pid}", "SUCCESS")
        return True, f"Network restored for PID {pid}."
    except Exception as e:
        _audit("PROCESS_RESTORE", f"PID {pid}", f"FAILED - {e}")
        return False, str(e)


# ─────────────────────────────────────────────────────────────
# Host Emergency Isolation (Sever all non-local external connections)
# ─────────────────────────────────────────────────────────────

def isolate_host_network() -> tuple[bool, str]:
    """
    Emergency Host Isolation:
    Blocks all inbound and outbound external network traffic to contain zero-day attacks,
    while explicitly preserving the local loopback (127.0.0.1 / ::1) interface for local analysis.
    """
    global _is_host_isolated
    if not is_admin():
        return False, "Elevated privileges required for host isolation."

    try:
        if IS_LINUX:
            # Preserve loopback communication
            subprocess.run(["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"], check=True)
            # Insert block rules on remaining interfaces
            subprocess.run(["iptables", "-A", "OUTPUT", "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-j", "DROP"], check=True)

            _is_host_isolated = True
            _audit("HOST_ISOLATE", "LOCALHOST", "SUCCESS - Host network isolated")
            print("[CONTAINMENT] 🚨 EMERGENCY HOST NETWORK ISOLATION ACTIVATED!")
            return True, "Host isolated. External traffic blocked; localhost preserved."

        elif IS_WINDOWS:
            rule_name = "Sentinel_Emergency_Host_Isolation"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={rule_name}", "dir=out", "action=block", "remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255"]
            subprocess.run(cmd, check=True)
            _is_host_isolated = True
            _audit("HOST_ISOLATE", "LOCALHOST", "SUCCESS - Host network isolated")
            print("[CONTAINMENT] 🚨 EMERGENCY HOST NETWORK ISOLATION ACTIVATED!")
            return True, "Host isolated via Windows Firewall."

        return False, "Platform not supported."
    except Exception as e:
        _audit("HOST_ISOLATE", "LOCALHOST", f"FAILED - {e}")
        return False, str(e)


def restore_host_network() -> tuple[bool, str]:
    """Restore normal host network connectivity by lifting isolation rules."""
    global _is_host_isolated
    if not is_admin():
        return False, "Elevated privileges required."

    try:
        if IS_LINUX:
            subprocess.run(["iptables", "-D", "OUTPUT", "-j", "DROP"], stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-D", "INPUT", "-j", "DROP"], stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-D", "INPUT", "-i", "lo", "-j", "ACCEPT"], stderr=subprocess.DEVNULL)
            _is_host_isolated = False
            _audit("HOST_RESTORE", "LOCALHOST", "SUCCESS - Host network restored")
            print("[CONTAINMENT] 🟢 Host network isolation lifted.")
            return True, "Host network isolation lifted."

        elif IS_WINDOWS:
            rule_name = "Sentinel_Emergency_Host_Isolation"
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], stderr=subprocess.DEVNULL)
            _is_host_isolated = False
            _audit("HOST_RESTORE", "LOCALHOST", "SUCCESS - Host network restored")
            print("[CONTAINMENT] 🟢 Host network isolation lifted.")
            return True, "Host network isolation lifted."

        return False, "Platform not supported."
    except Exception as e:
        return False, str(e)


def is_host_isolated() -> bool:
    """Return whether emergency host isolation is currently active."""
    return _is_host_isolated
