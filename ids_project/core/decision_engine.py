import logging
from core.rule_engine import evaluate_event
from core.ai_engine import analyze_event
from core.alert import trigger_alert

logger = logging.getLogger("IDS_DecisionEngine")

_subscribers = []

def subscribe(callback):
    """Register a callback function to receive (event_data, severity) tuples."""
    _subscribers.append(callback)

def _get_max_severity(sev1, sev2):
    levels = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "HIGH_FLOOD": 4}
    val1 = levels.get(sev1, 0)
    val2 = levels.get(sev2, 0)
    return sev1 if val1 >= val2 else sev2

def process_event(event_data, silent=False):
    """
    Passes event through Rule & AI engines and decides final severity by taking the maximum.
    If silent=True, skips logging to alerts.json.
    Returns: "HIGH_FLOOD", "HIGH", "MEDIUM", "LOW", or "NORMAL"
    """
    rule_severity = evaluate_event(event_data)
    ai_severity, ai_score = analyze_event(event_data)
    
    # Hybrid Combination Logic (Maximization)
    final_severity = _get_max_severity(rule_severity, ai_severity)
    base_severity = "HIGH" if final_severity == "HIGH_FLOOD" else final_severity
        
    if final_severity != "NORMAL":
        logger.info(f"Anomaly Detected! Final: {final_severity} (Rule: {rule_severity}, AI: {ai_severity}), Event ID: {event_data.get('event_id')}")
        if not silent:
            trigger_alert(base_severity, event_data, ai_score)
            
    # Broadcast to all UI listeners
    for callback in _subscribers:
        try:
            callback(event_data, final_severity)
        except Exception as e:
            logger.error(f"Error in subscriber callback: {e}")
            
    return base_severity
