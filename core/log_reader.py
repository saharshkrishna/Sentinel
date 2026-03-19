"""
log_reader.py - File watching and log buffering utilities.
"""

import asyncio
import logging
import threading
from collections import deque
from datetime import datetime
from typing import Dict, List, Callable, Awaitable

import aiofiles

logger = logging.getLogger(__name__)

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

async def tail_file(filepath: str, callback: Callable[[str], Awaitable[None]], run_flag: Callable[[], bool]):
    """
    Asynchronously tail a log file.
    
    :param filepath: Path to the log file.
    :param callback: Async function to call with each new log line.
    :param run_flag: Function returning boolean indicating if the tailer should keep running.
    """
    try:
        async with aiofiles.open(filepath, 'r') as f:
            await f.seek(0, 2)  # Seek to end
            while run_flag():
                line = await f.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                line = line.strip()
                if line:
                    await callback(line)
    except Exception as e:
        logger.error(f"Error tailing file {filepath}: {e}")
