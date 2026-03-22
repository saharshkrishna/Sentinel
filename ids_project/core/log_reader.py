import win32evtlog
import win32evtlogutil
import time
import logging
from config.settings import MONITOR_CHANNELS
from core.decision_engine import process_event
from core import process_tracker

logger = logging.getLogger("IDS_LogReader")

class LogReader:
    def __init__(self, silent=False):
        self.running = False
        self.handles = {}
        self.silent = silent
        
    def _open_handles(self):
        for channel in MONITOR_CHANNELS:
            try:
                hand = win32evtlog.OpenEventLog("localhost", channel)
                
                # Move pointer to the end by reading backwards once to ignore old events
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                win32evtlog.ReadEventLog(hand, flags, 0)
                
                self.handles[channel] = hand
                logger.info(f"[STATUS] Successfully opened '{channel}' event log.")
                print(f"[STATUS] Monitoring active on '{channel}' logs...")
            except Exception as e:
                logger.warning(f"[STATUS] Check skipped for '{channel}'. A required privilege is not held by the client, or log format is inaccessible. Exception: {e}")

    def _close_handles(self):
        for channel, hand in self.handles.items():
            try:
                win32evtlog.CloseEventLog(hand)
            except:
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
                                # Parse EventID safely
                                event_id = getattr(event, 'EventID', 0) & 0xFFFF
                                source_name = getattr(event, 'SourceName', 'Unknown')
                                event_type = getattr(event, 'EventType', 'Unknown')
                                
                                # Construct message safely avoiding missing attributes
                                try:
                                    msg = win32evtlogutil.SafeFormatMessage(event, channel)
                                except Exception:
                                    msg = None
                                    
                                if not msg:
                                    inserts = getattr(event, 'StringInserts', None)
                                    if inserts is not None:
                                        msg = " ".join([str(x) for x in inserts])
                                    else:
                                        msg = "N/A"
                                
                                # Construct event dictionary safely
                                event_data = {
                                    "event_id": event_id,
                                    "source": source_name,
                                    "event_type": event_type,
                                    "time_generated": event.TimeGenerated.Format() if hasattr(event, 'TimeGenerated') and event.TimeGenerated else "",
                                    "message": msg,
                                    "user": "Unknown"
                                }
                                
                                # Heuristic username extraction targeting EventIDs 4625
                                inserts = getattr(event, 'StringInserts', None)
                                if inserts and len(inserts) > 5:
                                    event_data["user"] = str(inserts[5])
                                
                                # Enrich with live process info
                                event_data = process_tracker.enrich(event_data)
                                
                                # Output live log to terminal
                                safe_msg = msg.replace('\r', '').replace('\n', ' ')
                                proc_label = event_data.get('process_name', source_name)
                                print(f"[EVENT] {proc_label[:20]:<20} | {event_id:<5} | {str(safe_msg)[:80]}...")
                                    
                                # Send to hybrid engine!
                                process_event(event_data, silent=self.silent)
                                
                            except Exception as inner_e:
                                logger.error(f"Error parsing specific event in {channel}: {inner_e}")
                except Exception as e:
                    logger.error(f"Continuous loop error reading events from {channel}: {e}")
            time.sleep(2) # Poll every 2 seconds

    def stop(self):
        self.running = False
        self._close_handles()
        logger.info("Log Reader stopped.")
