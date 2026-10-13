"""
process_control.py - Safe, audited process management actions for the IDS.
"""
import os
import subprocess
import logging
import datetime
import psutil
from pathlib import Path
from config.settings import LOG_DIR

logger = logging.getLogger("IDS_ProcessControl")
AUDIT_LOG = LOG_DIR / "audit.log"

from core.platform_adapter import is_process_protected, open_file_location as _platform_open_file


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


def kill_process(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """
    Safely terminate a process by PID.
    Returns (success: bool, message: str)
    """
    if _is_protected(process_name):
        msg = f"'{process_name}' is a protected system process and cannot be terminated."
        _audit("KILL", pid, process_name, f"BLOCKED - {msg}")
        return False, msg

    try:
        proc = psutil.Process(pid)
        proc.kill()
        _audit("KILL", pid, process_name, "SUCCESS")
        return True, f"Process '{process_name}' (PID {pid}) terminated successfully."
    except psutil.NoSuchProcess:
        msg = f"Process PID {pid} no longer exists."
        _audit("KILL", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except psutil.AccessDenied:
        msg = "Access denied. Try running the IDS as Administrator."
        _audit("KILL", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except Exception as e:
        _audit("KILL", pid, process_name, f"FAILED - {e}")
        return False, str(e)


def suspend_process(pid: int, process_name: str = "Unknown") -> tuple[bool, str]:
    """
    Suspend (pause) a process by PID.
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
        return True, f"Process '{process_name}' (PID {pid}) suspended."
    except psutil.NoSuchProcess:
        msg = f"Process PID {pid} no longer exists."
        _audit("SUSPEND", pid, process_name, f"FAILED - {msg}")
        return False, msg
    except psutil.AccessDenied:
        msg = "Access denied. Try running the IDS as Administrator."
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


def open_file_location(exe_path: str) -> tuple[bool, str]:
    """Open the native file manager (Explorer / xdg-open) to the directory containing the executable."""
    return _platform_open_file(exe_path)
