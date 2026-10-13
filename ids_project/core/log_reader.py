"""
log_reader.py - Cross-platform live system log ingestion for Windows and Linux.
On Windows: Reads native Windows Event Logs (System, Application, Security) via win32evtlog.
On Linux: Ingests structured logs from systemd-journal or fallback system log streams.
"""
import time
import logging
import datetime
import subprocess
import json
import os
from pathlib import Path
from core.platform_adapter import IS_WINDOWS, IS_LINUX
from core.decision_engine import process_event
from core import process_tracker

logger = logging.getLogger("IDS_LogReader")

# ─────────────────────────────────────────────────────────────
# Windows Event Log Reader
# ─────────────────────────────────────────────────────────────
if IS_WINDOWS:
    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        logger.error("pypiwin32 is not installed. Windows Event Log monitoring will fail.")

    class WindowsLogReader:
        def __init__(self, silent=False):
            from config.settings import MONITOR_CHANNELS
            self.running = False
            self.handles = {}
            self.silent = silent
            self.channels = MONITOR_CHANNELS

        def _open_handles(self):
            for channel in self.channels:
                try:
                    hand = win32evtlog.OpenEventLog("localhost", channel)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    win32evtlog.ReadEventLog(hand, flags, 0)
                    self.handles[channel] = hand
                    logger.info(f"[STATUS] Successfully opened '{channel}' event log.")
                    print(f"[STATUS] Monitoring active on '{channel}' logs...")
                except Exception as e:
                    logger.warning(f"[STATUS] Check skipped for '{channel}': {e}")

        def _close_handles(self):
            for channel, hand in self.handles.items():
                try:
                    win32evtlog.CloseEventLog(hand)
                except Exception:
                    pass
            self.handles = {}

        def start(self):
            self.running = True
            self._open_handles()
            logger.info("Log Reader started. Monitoring channels: " + ", ".join(self.handles.keys()))
            print("[STATUS] Fetching logs...")

            while self.running:
                for channel, hand in list(self.handles.items()):
                    try:
                        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        if events:
                            for event in events:
                                try:
                                    event_id = getattr(event, 'EventID', 0) & 0xFFFF
                                    source_name = getattr(event, 'SourceName', 'Unknown')
                                    event_type = getattr(event, 'EventType', 'Unknown')

                                    try:
                                        msg = win32evtlogutil.SafeFormatMessage(event, channel)
                                    except Exception:
                                        msg = None

                                    if not msg:
                                        inserts = getattr(event, 'StringInserts', None)
                                        msg = " ".join([str(x) for x in inserts]) if inserts else "N/A"

                                    event_data = {
                                        "event_id": event_id,
                                        "source": source_name,
                                        "event_type": event_type,
                                        "time_generated": event.TimeGenerated.Format() if hasattr(event, 'TimeGenerated') and event.TimeGenerated else "",
                                        "message": msg,
                                        "user": "Unknown"
                                    }

                                    inserts = getattr(event, 'StringInserts', None)
                                    if inserts and len(inserts) > 5:
                                        event_data["user"] = str(inserts[5])

                                    event_data = process_tracker.enrich(event_data)

                                    safe_msg = msg.replace('\r', '').replace('\n', ' ')
                                    proc_label = event_data.get('process_name', source_name)
                                    print(f"[EVENT] {proc_label[:20]:<20} | {event_id:<5} | {str(safe_msg)[:80]}...")

                                    process_event(event_data, silent=self.silent)

                                except Exception as inner_e:
                                    logger.error(f"Error parsing specific event in {channel}: {inner_e}")
                    except Exception as e:
                        logger.error(f"Continuous loop error reading events from {channel}: {e}")
                time.sleep(2)

        def stop(self):
            self.running = False
            self._close_handles()
            logger.info("Log Reader stopped.")


# ─────────────────────────────────────────────────────────────
# Linux Journal & System Log Reader
# ─────────────────────────────────────────────────────────────
class LinuxLogReader:
    def __init__(self, silent=False):
        self.running = False
        self.silent = silent

    def _start_systemd_python(self, journal_mod):
        """Read systemd journal using native python-systemd bindings."""
        try:
            reader = journal_mod.Reader()
            reader.seek_tail()
            reader.get_previous()  # Position cursor at current end
            print("[STATUS] Monitoring active on Linux systemd-journal...")
            logger.info("LinuxLogReader started via native systemd.journal.")

            while self.running:
                # Process available entries
                entries_read = 0
                while self.running:
                    entry = reader.get_next()
                    if not entry:
                        break
                    entries_read += 1
                    self._dispatch_journal_entry(entry)

                # Wait for new entries or short sleep
                reader.wait(1.5)
        except Exception as e:
            logger.error(f"Error in native systemd journal loop: {e}")

    def _start_journalctl_subprocess(self):
        """Fallback to journalctl -f -o json subprocess if native bindings fail."""
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json"]
        print("[STATUS] Monitoring active via journalctl stream...")
        logger.info("LinuxLogReader started via journalctl subprocess.")

        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            while self.running and proc.poll() is None:
                line = proc.stdout.readline()
                if line and line.strip():
                    try:
                        entry = json.loads(line)
                        self._dispatch_journal_entry(entry)
                    except Exception as e:
                        logger.debug(f"JSON parse error on journalctl line: {e}")
        except Exception as e:
            logger.error(f"Failed to run journalctl subprocess: {e}")
        finally:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass

    def _start_file_tailer(self):
        """Fallback: monitor accessible standard log files (/var/log/auth.log, secure, syslog)."""
        candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"]
        available_files = [p for p in candidates if os.path.exists(p) and os.access(p, os.R_OK)]

        if not available_files:
            print("[STATUS] Note: /var/log/ files require root privileges or group permissions to read.")
            logger.warning("No accessible system log files found in /var/log/.")
            while self.running:
                time.sleep(2)
            return

        print(f"[STATUS] Monitoring log files: {', '.join(available_files)}...")
        file_handles = {}
        for path in available_files:
            f = open(path, "r", encoding="utf-8", errors="ignore")
            f.seek(0, os.SEEK_END)  # Start at end
            file_handles[path] = f

        try:
            while self.running:
                had_data = False
                for path, f in file_handles.items():
                    line = f.readline()
                    if line:
                        had_data = True
                        self._dispatch_flat_line(line.strip(), os.path.basename(path))
                if not had_data:
                    time.sleep(1.5)
        finally:
            for f in file_handles.values():
                f.close()

    def _dispatch_journal_entry(self, entry: dict):
        """Normalize a journald dictionary and dispatch to the decision engine."""
        comm = str(entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER") or "System")
        pid_raw = entry.get("_PID")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None
        msg = str(entry.get("MESSAGE", "N/A"))
        user = str(entry.get("_AUDIT_LOGINUID") or entry.get("_UID") or "Unknown")

        event_data = {
            "event_id": 0,
            "source": comm,
            "event_type": str(entry.get("_AUDIT_TYPE_NAME") or entry.get("_TRANSPORT") or "Journal"),
            "time_generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": msg,
            "user": user,
            "pid": pid,
            "process_name": comm
        }

        # Enrich with live process tracker
        event_data = process_tracker.enrich(event_data)

        # Print live event to terminal
        safe_msg = msg.replace('\r', '').replace('\n', ' ')
        proc_label = event_data.get('process_name', comm)
        print(f"[EVENT] {proc_label[:20]:<20} | 0     | {str(safe_msg)[:80]}...")

        # Process through hybrid decision engine
        process_event(event_data, silent=self.silent)

    def _dispatch_flat_line(self, line: str, source_label: str):
        event_data = {
            "event_id": 0,
            "source": source_label,
            "event_type": "LogFile",
            "time_generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": line,
            "user": "Unknown"
        }
        event_data = process_tracker.enrich(event_data)
        proc_label = event_data.get('process_name', source_label)
        print(f"[EVENT] {proc_label[:20]:<20} | 0     | {line[:80]}...")
        process_event(event_data, silent=self.silent)

    def start(self):
        self.running = True
        logger.info("Starting Linux Log Reader...")

        # 1. Try native systemd-python
        try:
            import systemd.journal
            self._start_systemd_python(systemd.journal)
            return
        except Exception:
            pass

        # 2. Try journalctl command
        try:
            res = subprocess.run(["which", "journalctl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode == 0:
                self._start_journalctl_subprocess()
                return
        except Exception:
            pass

        # 3. Fallback to /var/log/ flat files
        self._start_file_tailer()

    def stop(self):
        self.running = False
        logger.info("Linux Log Reader stopped.")


# ─────────────────────────────────────────────────────────────
# Factory export
# ─────────────────────────────────────────────────────────────
LogReader = WindowsLogReader if IS_WINDOWS else LinuxLogReader
