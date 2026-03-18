"""
buffer.py - Thread-safe circular log buffer for maintaining log context.
"""

import threading
from collections import deque
from datetime import datetime
from typing import Dict, List


class LogBuffer:
    """Circular buffer for maintaining log context."""

    def __init__(self, size: int = 1000):
        self.buffer = deque(maxlen=size)
        self.lock = threading.Lock()

    def add(self, log_line: str):
        with self.lock:
            self.buffer.append({
                'timestamp': datetime.now().isoformat(),
                'log': log_line
            })

    def get_context(self, count: int = 10) -> List[Dict]:
        with self.lock:
            return list(self.buffer)[-count:]
