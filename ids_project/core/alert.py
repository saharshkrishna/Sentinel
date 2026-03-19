import json
import logging
from datetime import datetime
from config.settings import ALERTS_JSON_FILE

logger = logging.getLogger("IDS_Alerts")

def log_alert_to_file(alert_data):
    try:
        with open(ALERTS_JSON_FILE, "a") as f:
            json.dump(alert_data, f)
            f.write("\n")
    except Exception as e:
        logger.error(f"Failed to write alert to file: {e}")

def trigger_alert(severity, event_data, ai_score=0):
    timestamp = datetime.now().isoformat()
    alert_info = {
        "timestamp": timestamp,
        "severity": severity,
        "event_id": event_data.get('event_id'),
        "source": event_data.get('source'),
        "message": event_data.get('message', '')[:200], # Truncated
        "ai_score": ai_score
    }
    
    # Log it persistently
    # The Tray application will tail this file and show Toast notifications natively
    log_alert_to_file(alert_info)
    logger.info(f"Alert triggered: {alert_info}")
