"""
process_tracker.py - Enrich event_data with live process lineage, command-line arguments,
and parent-child relationships using psutil and the ProcessTree DAG.
"""
import psutil
import logging
from core.process_tree import get_process_tree, ProcessNode

logger = logging.getLogger("IDS_ProcessTracker")


def enrich(event_data: dict) -> dict:
    """
    Attempts to enrich event_data with live process information and lineage DAG metadata.
    Adds: process_name, exe_path, pid, ppid, parent_name, cmdline, lineage_str, process_status, lotl_rule.
    Falls back gracefully if no process info is available.
    """
    enriched = dict(event_data)
    tree = get_process_tree()

    proc_info = None

    # Attempt 1: Use PID from event_data if present
    pid = event_data.get("pid")
    if pid:
        proc_info = _get_by_pid(pid)
        # Ephemeral process support: query ProcessTree DAG if process already finished
        if not proc_info:
            try:
                node = tree.get_node(int(pid))
                if node:
                    proc_info = {
                        "process_name": node.name,
                        "exe_path": node.exe_path,
                        "pid": node.pid,
                        "ppid": node.ppid,
                        "cmdline": node.cmdline,
                        "process_status": "terminated"
                    }
            except (ValueError, TypeError):
                pass

    # Attempt 2: Match by source/service name if PID was absent or failed
    if not proc_info:
        source_name = event_data.get("source", "")
        if source_name and source_name not in ("Unknown", "Offline Scan"):
            proc_info = _get_by_name(source_name)

    if proc_info:
        enriched.update(proc_info)
        active_pid = proc_info.get("pid")

        # Update or query ProcessTree
        node = tree.get_node(active_pid) if active_pid else None
        if not node and active_pid:
            node = tree.add_or_update(
                pid=active_pid,
                ppid=proc_info.get("ppid", 0),
                name=proc_info.get("process_name", "Unknown"),
                cmdline=proc_info.get("cmdline", ""),
                exe_path=proc_info.get("exe_path", "N/A"),
                user=event_data.get("user", "Unknown")
            )

        if node:
            parent = tree.get_parent(node.pid)
            enriched["ppid"] = node.ppid
            enriched["parent_name"] = parent.name if parent else "Unknown"
            enriched["cmdline"] = node.cmdline
            enriched["lineage_str"] = tree.format_lineage_str(node.pid)

            # Check LotL heuristics
            is_suspicious, sev, rule = tree.evaluate_node(node)
            if is_suspicious:
                enriched["lotl_rule"] = rule
                enriched["lotl_severity"] = sev
        else:
            enriched["ppid"] = proc_info.get("ppid", None)
            enriched["parent_name"] = "Unknown"
            enriched["cmdline"] = proc_info.get("cmdline", "")
            enriched["lineage_str"] = "N/A"

        return enriched

    # Fallback: mark process info as unavailable
    if "process_name" not in enriched:
        enriched["process_name"] = event_data.get("source", "Unknown")
        enriched["exe_path"] = "N/A"
        enriched["pid"] = None
        enriched["ppid"] = None
        enriched["parent_name"] = "Unknown"
        enriched["cmdline"] = ""
        enriched["lineage_str"] = "N/A"
        enriched["process_status"] = "N/A"

    return enriched


def _get_by_pid(pid: int) -> dict | None:
    try:
        proc = psutil.Process(int(pid))
        ppid = proc.ppid() if hasattr(proc, 'ppid') else 0
        cmdline = " ".join(proc.cmdline() or [])
        return {
            "process_name": proc.name(),
            "exe_path": _safe_exe(proc),
            "pid": proc.pid,
            "ppid": ppid,
            "cmdline": cmdline,
            "process_status": proc.status(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return None


def _get_by_name(name: str) -> dict | None:
    """Find first running process whose name contains the given string (case-insensitive)."""
    name_lower = name.lower()
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "status"]):
        try:
            if name_lower in proc.info["name"].lower():
                cmdline = " ".join(proc.info.get("cmdline") or [])
                return {
                    "process_name": proc.info["name"],
                    "exe_path": proc.info["exe"] or "N/A",
                    "pid": proc.info["pid"],
                    "ppid": proc.info.get("ppid", 0),
                    "cmdline": cmdline,
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
