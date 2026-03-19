import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import threading
import logging
from config.settings import SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_DESCRIPTION
from core.log_reader import LogReader

logger = logging.getLogger("IDS_Service")

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
        logger.info("Service stop requested.")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        logger.info("Service running.")
        self.main()

    def main(self):
        # Start log reader in a separate thread so we can block on stop_event
        reader_thread = threading.Thread(target=self.log_reader.start, daemon=True)
        reader_thread.start()

        # Wait for stop signal
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        logger.info("Service exited gracefully.")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(IDSService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(IDSService)
