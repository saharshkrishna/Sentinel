import os
from pathlib import Path
import logging

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Application Logs
APP_LOG_FILE = LOG_DIR / "ids_app.log"
ALERTS_JSON_FILE = LOG_DIR / "alerts.json"

# Windows Event Log Settings
MONITOR_CHANNELS = ["System", "Application", "Security"]
# Specify events of interest. 
# 4625: Failed Logon
# 4624: Successful Logon (optional monitoring)
# 4648: Logon with explicit credentials
# 4776: Credential Validation
# 1102: Audit log cleared
# 4720: User account created
TARGET_EVENT_IDS = [4625, 4648, 4776, 1102, 4720]

# AI Engine Settings
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "deepseek-coder:6.7b"
OLLAMA_TIMEOUT = 60 # Seconds to wait for a response

# Detection Thresholds
FAILED_LOGIN_THRESHOLD = 5 # Number of failed logins before triggering rule within a time window
FAILED_LOGIN_WINDOW_SECONDS = 10

# Service Settings
SERVICE_NAME = "Sentinel"
SERVICE_DISPLAY_NAME = "Sentinel"
SERVICE_DESCRIPTION = "Background service for monitoring system logs and detecting anomalies using AI."

# Logging configuration
logging.basicConfig(
    filename=APP_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IDS_Config")
logger.info("Configuration loaded.")
