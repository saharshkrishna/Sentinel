"""
process_tracker.py - Enrich event_data with live process information using psutil.
"""
import psutil
import logging

logger = logging.getLogger("IDS_ProcessTracker")


def enrich(event_data: dict) -> dict:
    """
    Attempts to enrich event_data with live process information.
    Adds: process_name, exe_path, pid, process_status.
    Falls back gracefully if no process info is available.
    """
    enriched = dict(event_data)

    # Attempt 1: Use PID from event_data if present
    pid = event_data.get("pid")
    if pid:
        proc_info = _get_by_pid(pid)
        if proc_info:
            enriched.update(proc_info)
            return enriched

    # Attempt 2: Match by source/service name
    source_name = event_data.get("source", "")
    if source_name and source_name not in ("Unknown", "Offline Scan"):
        proc_info = _get_by_name(source_name)
        if proc_info:
            enriched.update(proc_info)
            return enriched

    # Fallback: mark process info as unavailable
    if "process_name" not in enriched:
        enriched["process_name"] = event_data.get("source", "Unknown")
        enriched["exe_path"] = "N/A"
        enriched["pid"] = None
        enriched["process_status"] = "N/A"

    return enriched


def _get_by_pid(pid: int) -> dict | None:
    try:
        proc = psutil.Process(int(pid))
        return {
            "process_name": proc.name(),
            "exe_path": _safe_exe(proc),
            "pid": proc.pid,
            "process_status": proc.status(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return None


def _get_by_name(name: str) -> dict | None:
    """Find first running process whose name contains the given string (case-insensitive)."""
    name_lower = name.lower()
    for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
        try:
            if name_lower in proc.info["name"].lower():
                return {
                    "process_name": proc.info["name"],
                    "exe_path": proc.info["exe"] or "N/A",
                    "pid": proc.info["pid"],
                    "process_status": proc.info["status"],
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _safe_exe(proc: psutil.Process) -> str:
    try:
        return proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return "N/A"
