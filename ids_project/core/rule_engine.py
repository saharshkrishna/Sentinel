from config.settings import FAILED_LOGIN_THRESHOLD, FAILED_LOGIN_WINDOW_SECONDS
from collections import defaultdict
import time
import logging
import re

logger = logging.getLogger("IDS_RuleEngine")

# State for tracking occurrences
failed_logins = defaultdict(list)

# Frequency/Flood tracking logic
event_history = defaultdict(list)
FLOOD_THRESHOLD = 20
FLOOD_WINDOW = 10  # seconds

# Severity mappings based on Professional Incident Response standards
HIGH_EVENTS = {4625, 4720, 4728, 7045, 1102}
MEDIUM_EVENTS = {7000, 7009, 17, 4688, 4672, 11707, 1033}
LOW_EVENTS = {10016, 1014, 4104, 4798, 78}

def evaluate_event(event_data):
    """
    Evaluates an event using professional rule-based heuristics.
    Returns categorized severity: "HIGH", "HIGH_FLOOD", "MEDIUM", "LOW", or "NORMAL"
    """
    event_id = event_data.get('event_id')
    message = event_data.get('message', '').lower()
    user = event_data.get('user', 'Unknown')
    current_time = time.time()
    
    # 0. Global Sliding-Window Frequency Matching
    if event_id:
        key = f"{event_id}_{user}"
        event_history[key] = [t for t in event_history[key] if current_time - t <= FLOOD_WINDOW]
        event_history[key].append(current_time)
        
        if len(event_history[key]) >= FLOOD_THRESHOLD:
            logger.warning(f"Rule Engine: FLOOD DETECTED for Event {event_id}.")
            return "HIGH_FLOOD"
    
    # 1. Pattern-based Rules (Suspicious Paths)
    suspicious_paths = [r"\\appdata\\(?:local|roaming)", r"\\temp\\", r"\\windows\\temp\\"]
    for pattern in suspicious_paths:
        if re.search(pattern, message):
            logger.warning(f"Rule Engine: Suspicious path execution detected.")
            return "HIGH"

    # 2. Offline / Raw Text Log Fallbacks
    if event_id is None or event_id == 0:
        if "failed login" in message or "unauthorized" in message:
            return "MEDIUM"
        if "error" in message or "exception" in message:
            return "LOW"
        return "NORMAL"
        
    # 3. Explicit Event ID Rules
    if event_id in HIGH_EVENTS:
        if event_id == 4625: # Failed login brute force logic
            failed_logins[user] = [t for t in failed_logins[user] if current_time - t <= FAILED_LOGIN_WINDOW_SECONDS]
            failed_logins[user].append(current_time)
            
            if len(failed_logins[user]) >= FAILED_LOGIN_THRESHOLD:
                logger.warning(f"Rule Engine: Brute force detected for {user}.")
                return "HIGH"
            return "MEDIUM" # Single failure is medium severity
        return "HIGH"
        
    if event_id in MEDIUM_EVENTS:
        return "MEDIUM"
        
    if event_id in LOW_EVENTS:
        return "LOW"
        
    # Ignore / noise filtering
    return "NORMAL"
