"""
service_runner.py - Background service runner for Windows (Win32 Service) and Linux (systemd).
"""
import sys
import os
import subprocess
import threading
import logging
from pathlib import Path
from config.settings import SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_DESCRIPTION
from core.platform_adapter import IS_WINDOWS, IS_LINUX, is_admin
from core.log_reader import LogReader

logger = logging.getLogger("IDS_Service")

# ─────────────────────────────────────────────────────────────
# Windows Service Implementation
# ─────────────────────────────────────────────────────────────
if IS_WINDOWS:
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager

        class IDSService(win32serviceutil.ServiceFramework):
            _svc_name_ = SERVICE_NAME
            _svc_display_name_ = SERVICE_DISPLAY_NAME
            _svc_description_ = SERVICE_DESCRIPTION

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)
                self.log_reader = LogReader()

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.stop_event)
                self.log_reader.stop()
                logger.info("Windows Service stop requested.")

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                logger.info("Windows Service running.")
                self.main()

            def main(self):
                reader_thread = threading.Thread(target=self.log_reader.start, daemon=True)
                reader_thread.start()
                win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
                logger.info("Windows Service exited gracefully.")
    except ImportError:
        IDSService = None
else:
    IDSService = None


# ─────────────────────────────────────────────────────────────
# Linux systemd Service Manager
# ─────────────────────────────────────────────────────────────
SYSTEMD_UNIT_PATH = Path("/etc/systemd/system/sentinel.service")

def _generate_systemd_unit() -> str:
    current_dir = Path(__file__).resolve().parent.parent
    python_bin = sys.executable
    main_script = current_dir / "main.py"
    
    return f"""[Unit]
Description={SERVICE_DESCRIPTION}
After=network.target

[Service]
Type=simple
WorkingDirectory={current_dir}
ExecStart={python_bin} {main_script} --console
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""

def handle_linux_service(action: str):
    """Manage Sentinel as a Linux systemd background service."""
    if not is_admin():
        print("ERROR: Linux systemd service management requires root privileges (sudo).")
        sys.exit(1)

    if action == "install":
        try:
            unit_content = _generate_systemd_unit()
            SYSTEMD_UNIT_PATH.write_text(unit_content, encoding="utf-8")
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "sentinel.service"], check=True)
            print("Successfully installed and enabled sentinel.service via systemd.")
            print("Start it anytime with: sudo systemctl start sentinel")
        except Exception as e:
            print(f"Failed to install systemd service: {e}")

    elif action == "start":
        try:
            subprocess.run(["systemctl", "start", "sentinel.service"], check=True)
            print("Started sentinel.service.")
        except Exception as e:
            print(f"Failed to start service: {e}")

    elif action == "stop":
        try:
            subprocess.run(["systemctl", "stop", "sentinel.service"], check=True)
            print("Stopped sentinel.service.")
        except Exception as e:
            print(f"Failed to stop service: {e}")

    elif action == "remove":
        try:
            subprocess.run(["systemctl", "stop", "sentinel.service"], stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "sentinel.service"], stderr=subprocess.DEVNULL)
            if SYSTEMD_UNIT_PATH.exists():
                SYSTEMD_UNIT_PATH.unlink()
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            print("Removed sentinel.service.")
        except Exception as e:
            print(f"Failed to remove service: {e}")


def handle_service_command(action: str):
    """Universal dispatcher for background service management."""
    if IS_WINDOWS:
        if IDSService is None:
            print("ERROR: pywin32 is required to run Windows Services.")
            sys.exit(1)
        sys.argv = ['service_runner.py', action]
        import win32serviceutil
        win32serviceutil.HandleCommandLine(IDSService)
    else:
        handle_linux_service(action)


if __name__ == '__main__':
    if IS_WINDOWS and IDSService:
        if len(sys.argv) == 1:
            import servicemanager
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(IDSService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            import win32serviceutil
            win32serviceutil.HandleCommandLine(IDSService)
    else:
        if len(sys.argv) > 1:
            handle_linux_service(sys.argv[1])
        else:
            print("Usage: python service_runner.py [install|start|stop|remove]")
