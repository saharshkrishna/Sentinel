"""
canary_sentry.py - Active Deception & Anti-Ransomware Tripwire Subsystem.
Deploys decoy canary files in strategic system directories and actively monitors
them for unauthorized modification, rename, or deletion. Automatically freezes
(suspends) offending ransomware processes before mass file encryption occurs.
"""
import os
import sys
import time
import uuid
import hashlib
import logging
import threading
from pathlib import Path
import psutil

from core.platform_adapter import IS_WINDOWS, IS_LINUX, is_process_protected
from core import process_control
from core.decision_engine import process_event
from config.settings import ENABLE_CANARY_SENTRY, CANARY_AUTOSUSPEND_PROCESS

logger = logging.getLogger("IDS_CanarySentry")

# Standard decoy file templates designed to be targeted early during ransomware traversal
CANARY_TEMPLATES = [
    ("!_financial_q4_audit_records.xlsx", "MOCK-EXCEL-HEADER-CONFIDENTIAL-FINANCIAL-SHEET\nAccount,Balance,Status\nUS984128,450000,ACTIVE\n"),
    ("!_confidential_passwords_vault.docx", "MOCK-WORD-HEADER-ENTERPRISE-PASSWORD-CREDENTIALS\nAdmin: SuperSecret2026!\nDB_Root: db_pass_vault\n"),
    ("!_system_recovery_backup_keys.txt", "# SENTINEL CANARY DECOY FILE\nPRIVATE_KEY=MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n")
]


def _compute_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""


def get_default_canary_dirs() -> list[Path]:
    """Identify optimal target directories for deploying canary decoys."""
    dirs = []
    home = Path.home()

    if IS_WINDOWS:
        docs = home / "Documents"
        desktop = home / "Desktop"
        appdata = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        for d in [docs, desktop, appdata]:
            if d.exists() and d.is_dir():
                dirs.append(d)
    else:
        docs = home / "Documents"
        config = home / ".config"
        tmp_dir = Path("/tmp")
        for d in [docs, config, tmp_dir]:
            if d.exists() and d.is_dir():
                dirs.append(d)

    # Fallback to home if no candidate directories found
    if not dirs and home.exists():
        dirs.append(home)

    return dirs


class CanarySentry:
    def __init__(self, target_dirs: list[Path] | None = None):
        self.enabled = ENABLE_CANARY_SENTRY
        self.auto_suspend = CANARY_AUTOSUSPEND_PROCESS
        self.target_dirs = target_dirs or get_default_canary_dirs()
        self.canaries: dict[str, dict] = {}  # filepath_str -> metadata
        self.running = False
        self._watcher_thread = None
        self._tripped = False
        self._inotify_notifier = None

    def deploy_canaries(self):
        """Deploy signed decoy canary files into target directories."""
        self.canaries.clear()
        for d in self.target_dirs:
            for filename, content in CANARY_TEMPLATES:
                file_path = d / filename
                token = str(uuid.uuid4())
                payload = f"# SENTINEL_CANARY_TOKEN:{token}\n{content}".encode("utf-8")
                try:
                    with open(file_path, "wb") as f:
                        f.write(payload)

                    file_hash = _compute_hash(file_path)
                    self.canaries[str(file_path.resolve())] = {
                        "path": file_path,
                        "token": token,
                        "hash": file_hash,
                        "size": len(payload),
                        "mtime": file_path.stat().st_mtime
                    }
                    logger.info(f"Deployed canary decoy at: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to deploy canary at {file_path}: {e}")

        logger.info(f"CanarySentry deployed {len(self.canaries)} active decoys across {len(self.target_dirs)} directories.")
        print(f"[CANARY] Deployed {len(self.canaries)} ransomware canary decoys.")

    def cleanup_canaries(self):
        """Safely remove deployed canary decoy files."""
        for path_str, meta in list(self.canaries.items()):
            try:
                p = meta["path"]
                if p.exists():
                    p.unlink()
                    logger.info(f"Cleaned up canary: {p}")
            except Exception as e:
                logger.debug(f"Could not remove canary {path_str}: {e}")
        self.canaries.clear()

    def find_offending_process(self, file_path: Path) -> tuple[int | None, str]:
        """
        Identify which process currently has the canary file open or recently accessed it.
        Uses process open file descriptor inspection.
        """
        target_str = str(file_path.resolve())

        # 1. Direct open file handle inspection across running processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                open_files = proc.open_files()
                for of in open_files:
                    if of.path == target_str:
                        return proc.pid, proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 2. Linux-specific /proc check for rapid accuracy
        if IS_LINUX:
            try:
                for pid_dir in Path("/proc").glob("[0-9]*"):
                    try:
                        fd_dir = pid_dir / "fd"
                        if fd_dir.exists():
                            for fd in fd_dir.iterdir():
                                try:
                                    if fd.is_symlink() and str(fd.resolve()) == target_str:
                                        pid = int(pid_dir.name)
                                        name = psutil.Process(pid).name()
                                        return pid, name
                                except (OSError, psutil.NoSuchProcess):
                                    continue
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception:
                pass

        return None, "Unknown"

    def handle_canary_trip(self, file_path: Path, action_type: str = "TAMPERED"):
        """Handle a tripped canary file: suspend process, emit critical alert."""
        if not self.running:
            return

        path_str = str(file_path.resolve())
        meta = self.canaries.get(path_str)
        if not meta:
            return

        pid, proc_name = self.find_offending_process(file_path)
        logger.critical(f"RANSOMWARE TRIPWIRE TRIGGERED! Action: {action_type} on {file_path}. Suspect: {proc_name} (PID: {pid})")
        print(f"\n[ALERT] 🚨 RANSOMWARE CANARY TRIPPED! Decoy '{file_path.name}' was {action_type}!")

        # Automated Containment Action: Freeze the offending process
        suspend_msg = "Process not identified"
        if pid and self.auto_suspend:
            if is_process_protected(proc_name):
                suspend_msg = f"Protected system process '{proc_name}' was not suspended."
            else:
                ok, msg = process_control.suspend_process(pid, proc_name)
                suspend_msg = f"Offending process '{proc_name}' (PID {pid}) AUTO-SUSPENDED: {msg}"
                print(f"[CONTAINMENT] ⏸ {suspend_msg}")

        # Dispatch critical alert to Decision Engine
        event_data = {
            "event_id": 9999,
            "source": "CanarySentry",
            "event_type": "RansomwareTripwire",
            "time_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "message": (
                f"CRITICAL RANSOMWARE ACTIVITY! Decoy canary file '{file_path.name}' was {action_type}. "
                f"Suspect: {proc_name} (PID {pid}). {suspend_msg}."
            ),
            "user": "System",
            "pid": pid,
            "process_name": proc_name,
            "exe_path": "N/A"
        }

        # Maximization logic treats this as HIGH/CRITICAL
        process_event(event_data, silent=False)

    def _poll_watch_loop(self):
        """Cross-platform polling watchdog verifying canary file integrity."""
        while self.running:
            for path_str, meta in list(self.canaries.items()):
                p = meta["path"]
                if not p.exists():
                    self.handle_canary_trip(p, "DELETED / RENAMED")
                    continue

                try:
                    stat = p.stat()
                    # Check modification time or size mismatch
                    if stat.st_mtime != meta["mtime"] or stat.st_size != meta["size"]:
                        current_hash = _compute_hash(p)
                        if current_hash != meta["hash"]:
                            self.handle_canary_trip(p, "ENCRYPTED / MODIFIED")
                            meta["hash"] = current_hash
                            meta["mtime"] = stat.st_mtime
                except Exception as e:
                    logger.debug(f"Stat check failed for canary {path_str}: {e}")

            time.sleep(1.0)

    def _start_pyinotify_watcher(self):
        """Linux-native inotify real-time watcher."""
        try:
            import pyinotify

            sentry_self = self

            class CanaryEventHandler(pyinotify.ProcessEvent):
                def process_IN_MODIFY(self, event):
                    sentry_self._check_event(event.pathname, "MODIFIED")

                def process_IN_CLOSE_WRITE(self, event):
                    sentry_self._check_event(event.pathname, "OVERWRITTEN")

                def process_IN_MOVED_FROM(self, event):
                    sentry_self._check_event(event.pathname, "RENAMED")

                def process_IN_DELETE(self, event):
                    sentry_self._check_event(event.pathname, "DELETED")

            wm = pyinotify.WatchManager()
            mask = pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_FROM | pyinotify.IN_DELETE

            for d in self.target_dirs:
                try:
                    wm.add_watch(str(d), mask, rec=False)
                except Exception as e:
                    logger.debug(f"Could not watch directory {d} with inotify: {e}")

            handler = CanaryEventHandler()
            self._inotify_notifier = pyinotify.ThreadedNotifier(wm, handler)
            self._inotify_notifier.start()
            logger.info("CanarySentry pyinotify real-time watcher started.")
        except Exception as e:
            logger.warning(f"pyinotify initialization failed, falling back to polling: {e}")

    def _check_event(self, pathname: str, action: str):
        resolved = str(Path(pathname).resolve())
        if resolved in self.canaries:
            self.handle_canary_trip(self.canaries[resolved]["path"], action)

    def start(self):
        """Start the canary sentry subsystem."""
        if not self.enabled:
            logger.info("CanarySentry is disabled in settings.")
            return

        self.running = True
        self.deploy_canaries()

        # Try starting real-time inotify watcher on Linux
        if IS_LINUX:
            self._start_pyinotify_watcher()

        # Always start polling loop for redundancy and cross-platform integrity
        self._watcher_thread = threading.Thread(target=self._poll_watch_loop, daemon=True, name="CanaryWatcherThread")
        self._watcher_thread.start()
        logger.info("CanarySentry active and monitoring decoy tripwires.")

    def stop(self, cleanup: bool = False):
        """Stop the canary sentry subsystem."""
        self.running = False
        if self._inotify_notifier:
            try:
                self._inotify_notifier.stop()
            except Exception:
                pass
        if cleanup:
            self.cleanup_canaries()
        logger.info("CanarySentry stopped.")


# Global instance
_global_sentry: CanarySentry | None = None


def get_canary_sentry() -> CanarySentry:
    """Retrieve or initialize the singleton CanarySentry instance."""
    global _global_sentry
    if _global_sentry is None:
        _global_sentry = CanarySentry()
    return _global_sentry
