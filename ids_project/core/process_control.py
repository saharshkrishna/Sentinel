"""
process_control.py - Safe, audited process management and containment actions for Sentinel.
Integrates pre-termination digital forensics preservation, process network cutting,
and emergency host containment.
"""
import os
import subprocess
import logging
import datetime
import psutil
from pathlib import Path
from config.settings import LOG_DIR, ENABLE_PRE_KILL_FORENSICS
from core.platform_adapter import is_process_protected, open_file_location as _platform_open_file

logger = logging.getLogger("IDS_ProcessControl")
AUDIT_LOG = LOG_DIR / "audit.log"


def _audit(action: str, pid, process_name: str, result: str):
    """Append an audit record to logs/audit.log."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] ACTION={action} | PID={pid} | Process={process_name} | Result={result}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
    logger.info(entry.strip())


def _is_protected(process_name: str) -> bool:
    return is_process_protected(process_name)


def capture_snapshot(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """Capture on-demand digital forensics snapshot of a process."""
    try:
        from core.forensics import capture_process_snapshot
        snapshot = capture_process_snapshot(pid, process_name, reason="Manual operator forensic capture")
        return True, f"Forensic snapshot saved to: logs/forensics/ (SHA-256: {snapshot['binary_hashes']['sha256'][:16]}...)"
    except Exception as e:
        logger.error(f"Manual forensics capture failed: {e}")
        return False, str(e)


def kill_process(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """
    Safely terminate a process by PID with pre-termination digital forensics preservation.
    Returns (success: bool, message: str)
    """
    if _is_protected(process_name):
        msg = f"'{process_name}' is a protected system process and cannot be terminated."
        _audit("KILL", pid, process_name, f"BLOCKED - {msg}")
        return False, msg

    # Pre-termination digital forensics preservation
    if ENABLE_PRE_KILL_FORENSICS:
        try:
            from core.forensics import capture_process_snapshot
            capture_process_snapshot(pid, process_name, reason="Pre-termination automated forensic preservation")
        except Exception as e:
            logger.warning(f"Pre-kill forensics snapshot warning for PID {pid}: {e}")

    try:
        proc = psutil.Process(pid)
        proc.kill()
        _audit("KILL", pid, process_name, "SUCCESS")
        return True, f"Process '{process_name}' (PID {pid}) terminated successfully. Forensics preserved."
    except psutil.NoSuchProcess:
        msg = f"Process PID {pid} no longer exists."
        _audit("KILL", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except psutil.AccessDenied:
        msg = "Access denied. Try running Sentinel with elevated root / Administrator privileges."
        _audit("KILL", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except Exception as e:
        _audit("KILL", pid, process_name, f"FAILED - {e}")
        return False, str(e)


def suspend_process(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """
    Suspend (pause in memory) a process by PID.
    Returns (success: bool, message: str)
    """
    if _is_protected(process_name):
        msg = f"'{process_name}' is a protected system process and cannot be suspended."
        _audit("SUSPEND", pid, process_name, f"BLOCKED - {msg}")
        return False, msg

    try:
        proc = psutil.Process(pid)
        proc.suspend()
        _audit("SUSPEND", pid, process_name, "SUCCESS")
        return True, f"Process '{process_name}' (PID {pid}) suspended in memory."
    except psutil.NoSuchProcess:
        msg = f"Process PID {pid} no longer exists."
        _audit("SUSPEND", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except psutil.AccessDenied:
        msg = "Access denied. Try running Sentinel with elevated root / Administrator privileges."
        _audit("SUSPEND", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except Exception as e:
        _audit("SUSPEND", pid, process_name, f"FAILED - {e}")
        return False, str(e)


def resume_process(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """Resume a previously suspended process."""
    try:
        proc = psutil.Process(pid)
        proc.resume()
        _audit("RESUME", pid, process_name, "SUCCESS")
        return True, f"Process '{process_name}' (PID {pid}) resumed."
    except Exception as e:
        _audit("RESUME", pid, process_name, f"FAILED - {e}")
        return False, str(e)


def isolate_process_network(pid: int, process_name: str = "Unknown", exe_path: str = "") -> tuple[bool, str]:
    """Cut network connectivity for a specific process PID."""
    from core import network_guard
    return network_guard.isolate_process_network(pid, process_name, exe_path)


def restore_process_network(pid: int) -> tuple[bool, str]:
    """Restore network connectivity for a specific process PID."""
    from core import network_guard
    return network_guard.restore_process_network(pid)


def isolate_host() -> tuple[bool, str]:
    """Enforce emergency workstation host network isolation."""
    from core import network_guard
    return network_guard.isolate_host_network()


def restore_host() -> tuple[bool, str]:
    """Restore normal workstation host network connectivity."""
    from core import network_guard
    return network_guard.restore_host_network()


def is_host_isolated() -> bool:
    """Query current host network isolation status."""
    from core import network_guard
    return network_guard.is_host_isolated()


def open_file_location(exe_path: str) -> tuple[bool, str]:
    """Open the native file manager (Explorer / xdg-open) to the directory containing the executable."""
    return _platform_open_file(exe_path)
