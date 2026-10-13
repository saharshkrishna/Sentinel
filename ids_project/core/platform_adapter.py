"""
platform_adapter.py - Cross-platform OS abstraction layer for Windows and Linux.
Provides platform-safe primitives for privilege checks, file exploration,
process protection, and OS detection.
"""
import os
import sys
import platform
import subprocess
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_DARWIN = platform.system() == "Darwin"

# Critical system processes that must never be suspended or terminated
WINDOWS_PROTECTED_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
    "dwm.exe", "registry", "memory compression"
}

LINUX_PROTECTED_PROCESSES = {
    "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
    "dbus-daemon", "sshd", "systemd-journald", "systemd-resolved",
    "systemd-udevd", "systemd-logind", "cron", "crond", "auditd",
    "bash", "sh", "login", "agetty"
}

PROTECTED_PROCESSES = WINDOWS_PROTECTED_PROCESSES | LINUX_PROTECTED_PROCESSES


def is_admin() -> bool:
    """
    Checks if the script is running with administrative (Windows) or root (Linux) privileges.
    """
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def is_process_protected(process_name: str) -> bool:
    """Check if process name is in protected list (case-insensitive)."""
    if not process_name:
        return False
    name_clean = process_name.lower().strip()
    return name_clean in PROTECTED_PROCESSES


def open_file_location(path_str: str) -> tuple[bool, str]:
    """
    Open the native OS file explorer pointing to the target file or directory.
    Supports Windows Explorer, Linux xdg-open/nautilus, and macOS open.
    """
    if not path_str or path_str == "N/A":
        return False, "No file path available for this process."

    try:
        path = Path(path_str)
        if not path.exists():
            return False, f"Path does not exist: {path_str}"

        if IS_WINDOWS:
            subprocess.Popen(["explorer", "/select,", str(path)])
            return True, "Windows Explorer opened."
        elif IS_LINUX:
            parent_dir = str(path.parent if path.is_file() else path)
            subprocess.Popen(["xdg-open", parent_dir])
            return True, "File manager opened."
        elif IS_DARWIN:
            subprocess.Popen(["open", "-R", str(path)])
            return True, "Finder opened."
        else:
            return False, f"Unsupported operating system: {platform.system()}"
    except Exception as e:
        return False, str(e)
