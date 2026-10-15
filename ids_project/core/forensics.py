"""
forensics.py - Digital Forensics Vault & Pre-Termination Volatile Memory Preservation.
Captures process memory dumps, SHA-256/MD5 disk binary hashes, open network sockets,
command-line parameters, and environment state prior to process termination.
"""
import os
import sys
import time
import json
import hashlib
import logging
import datetime
import subprocess
from pathlib import Path
import psutil

from core.platform_adapter import IS_WINDOWS, IS_LINUX
from core.process_tree import get_process_tree
from config.settings import FORENSICS_DIR, LOG_DIR

logger = logging.getLogger("IDS_Forensics")
AUDIT_LOG = LOG_DIR / "audit.log"


def _compute_hashes(filepath: Path) -> dict[str, str]:
    """Compute SHA-256 and MD5 hashes of a target executable file on disk."""
    hashes = {"sha256": "N/A", "md5": "N/A"}
    if not filepath or not filepath.exists() or not filepath.is_file():
        return hashes

    try:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        hashes["sha256"] = sha256.hexdigest()
        hashes["md5"] = md5.hexdigest()
    except Exception as e:
        logger.debug(f"Failed to hash executable {filepath}: {e}")

    return hashes


def _dump_windows_minidump(pid: int, output_path: Path) -> bool:
    """Capture Windows volatile process memory dump using dbghelp.dll MiniDumpWriteDump."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        dbghelp = ctypes.windll.dbghelp

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MiniDumpWithNormal = 0x00000000
        MiniDumpWithDataSegs = 0x00000001
        dump_flags = MiniDumpWithNormal | MiniDumpWithDataSegs

        hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not hProcess:
            return False

        try:
            with open(output_path, "wb") as f:
                hFile = wintypes.HANDLE(f.fileno())
                res = dbghelp.MiniDumpWriteDump(
                    hProcess,
                    pid,
                    hFile,
                    dump_flags,
                    None,
                    None,
                    None
                )
                return bool(res)
        finally:
            kernel32.CloseHandle(hProcess)
    except Exception as e:
        logger.error(f"Windows MiniDumpWriteDump failed for PID {pid}: {e}")
        return False


def _dump_linux_proc_memory(pid: int, snapshot_dir: Path) -> dict:
    """Capture Linux process memory maps, status, command line, and core dumps."""
    captured = {}
    proc_root = Path(f"/proc/{pid}")
    if not proc_root.exists():
        return captured

    # 1. Memory address mappings (/proc/<pid>/maps)
    try:
        maps_file = proc_root / "maps"
        if maps_file.exists():
            dest = snapshot_dir / "proc_maps.txt"
            dest.write_text(maps_file.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            captured["maps"] = str(dest)
    except Exception as e:
        logger.debug(f"Failed to read /proc/{pid}/maps: {e}")

    # 2. Process status & thread information (/proc/<pid>/status)
    try:
        status_file = proc_root / "status"
        if status_file.exists():
            dest = snapshot_dir / "proc_status.txt"
            dest.write_text(status_file.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            captured["status"] = str(dest)
    except Exception as e:
        logger.debug(f"Failed to read /proc/{pid}/status: {e}")

    # 3. Environment variables (/proc/<pid>/environ)
    try:
        environ_file = proc_root / "environ"
        if environ_file.exists():
            dest = snapshot_dir / "proc_environ.txt"
            raw = environ_file.read_bytes()
            # Replace null bytes with newlines for human-readable audit
            dest.write_text(raw.replace(b"\x00", b"\n").decode("utf-8", errors="ignore"), encoding="utf-8")
            captured["environ"] = str(dest)
    except Exception as e:
        logger.debug(f"Failed to read /proc/{pid}/environ: {e}")

    # 4. Attempt gcore if installed on the host
    try:
        core_out = snapshot_dir / f"core.{pid}"
        res = subprocess.run(["gcore", "-o", str(snapshot_dir / "core"), str(pid)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if res.returncode == 0:
            captured["core_dump"] = str(core_out)
    except Exception:
        pass

    return captured


def capture_process_snapshot(pid: int, process_name: str = "Unknown", reason: str = "") -> dict:
    """
    Capture a digital forensics snapshot of a process before suspension or termination.
    Preserves volatile memory, binary disk hashes, open sockets, and command line history.
    Returns the forensic manifest dictionary.
    """
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_proc_name = "".join(c for c in process_name if c.isalnum() or c in "._-") or "proc"
    snapshot_dir = FORENSICS_DIR / f"{timestamp_str}_{pid}_{clean_proc_name}"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    proc_info = {
        "pid": pid,
        "process_name": process_name,
        "timestamp": datetime.datetime.now().isoformat(),
        "reason": reason or "Routine pre-termination digital forensics preservation",
        "ppid": None,
        "parent_name": "Unknown",
        "exe_path": "N/A",
        "cmdline": "",
        "username": "Unknown",
        "create_time": None,
        "status": "Unknown",
        "threads": 0,
        "binary_hashes": {"sha256": "N/A", "md5": "N/A"},
        "network_connections": [],
        "open_files": [],
        "artifacts_captured": {}
    }

    # Query live psutil process metadata
    try:
        proc = psutil.Process(pid)
        proc_info["ppid"] = proc.ppid() if hasattr(proc, 'ppid') else None
        proc_info["cmdline"] = " ".join(proc.cmdline() or [])
        proc_info["username"] = proc.username() if hasattr(proc, 'username') else "Unknown"
        proc_info["create_time"] = proc.create_time() if hasattr(proc, 'create_time') else None
        proc_info["status"] = proc.status()
        proc_info["threads"] = proc.num_threads()

        try:
            exe_str = proc.exe()
            proc_info["exe_path"] = exe_str or "N/A"
            if exe_str and Path(exe_str).exists():
                proc_info["binary_hashes"] = _compute_hashes(Path(exe_str))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Capture active network sockets
        try:
            connections = proc.net_connections(kind='inet')
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                proc_info["network_connections"].append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Capture open files
        try:
            proc_info["open_files"] = [f.path for f in proc.open_files()]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Process already terminated; retrieve from ProcessTree DAG
        tree = get_process_tree()
        node = tree.get_node(pid)
        if node:
            proc_info["ppid"] = node.ppid
            proc_info["cmdline"] = node.cmdline
            proc_info["exe_path"] = node.exe_path
            proc_info["username"] = node.user
            proc_info["status"] = "Terminated (Extracted from ProcessTree DAG)"
            if node.exe_path and node.exe_path != "N/A" and Path(node.exe_path).exists():
                proc_info["binary_hashes"] = _compute_hashes(Path(node.exe_path))

    # Capture memory dumps
    if IS_WINDOWS:
        dump_file = snapshot_dir / f"minidump_{pid}.dmp"
        if _dump_windows_minidump(pid, dump_file):
            proc_info["artifacts_captured"]["windows_minidump"] = str(dump_file)
    elif IS_LINUX:
        linux_artifacts = _dump_linux_proc_memory(pid, snapshot_dir)
        proc_info["artifacts_captured"].update(linux_artifacts)

    # Write forensic manifest.json
    manifest_file = snapshot_dir / "manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(proc_info, f, indent=2)

    # Log to audit.log
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_entry = (
        f"[{ts}] ACTION=FORENSIC_SNAPSHOT | PID={pid} | Process={process_name} | "
        f"SHA256={proc_info['binary_hashes']['sha256']} | Path={snapshot_dir}\n"
    )
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(audit_entry)
    except Exception as e:
        logger.error(f"Failed to append forensic audit: {e}")

    logger.info(f"Captured forensic snapshot for PID {pid} ({process_name}) at {snapshot_dir}")
    print(f"[FORENSICS] 📸 Preserved digital snapshot: {snapshot_dir.name} (SHA-256: {proc_info['binary_hashes']['sha256'][:16]}...)")

    return proc_info
