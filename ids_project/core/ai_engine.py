import requests
import logging
from functools import lru_cache
from config.settings import OLLAMA_ENDPOINT, OLLAMA_MODEL, OLLAMA_TIMEOUT

logger = logging.getLogger("IDS_AIEngine")

@lru_cache(maxsize=1000)
def _cached_api_call(message):
    prompt = (
        "You are an advanced cybersecurity intrusion detection system.\n"
        "Analyze the given Windows event log and classify it into one of the following categories:\n"
        "HIGH, MEDIUM, LOW, NORMAL.\n\n"
        "Consider:\n"
        "- Event type and severity\n"
        "- Frequency of occurrence\n"
        "- Suspicious patterns or repetition\n"
        "- System anomalies\n\n"
        "If an event is repeated excessively in a short time, classify as HIGH.\n\n"
        "Respond with only ONE word.\n\n"
        f"Log:\n{message}"
    )
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=OLLAMA_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        result_text = data.get("response", "").strip().upper()
        
        if "HIGH_FLOOD" in result_text: return "HIGH_FLOOD", 90
        if "HIGH" in result_text: return "HIGH", 90
        if "MEDIUM" in result_text: return "MEDIUM", 60
        if "LOW" in result_text: return "LOW", 30
        return "NORMAL", 0
        
    except requests.exceptions.RequestException as e:
        logger.error(f"AI Engine Error over API: {e}")
        return "NORMAL", 0

def analyze_event(event_data):
    """
    Sends event details to local Ollama model for analysis.
    Uses LRU cache to prevent duplicated slow requests on repetitive logs.
    Returns (severity: str, score: int 0-100)
    """
    message = event_data.get('message', '')
    if not message or message == "N/A":
        return "NORMAL", 0
        
    return _cached_api_call(message)
