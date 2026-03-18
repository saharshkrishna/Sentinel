"""
ai_analyzer.py - AI-powered log analysis using Ollama API with rate limiting.
"""

import asyncio
import json
import re
import time
import logging
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class OllamaAnalyzer:
    """AI-powered log analysis using Ollama."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url
        self.model = model
        self.session: Optional[aiohttp.ClientSession] = None
        self.enabled = True
        self.last_call: float = 0.0
        self.rate_limit: float = 1.0

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create session for the current loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None

        if self.session is None or self.session.closed or (hasattr(self.session, '_loop') and self.session._loop != loop):
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = aiohttp.ClientSession()
        return self.session

    async def initialize(self):
        await self._get_session()

    async def analyze(self, log_line: str, context: List[Dict]) -> Optional[Dict]:
        session = await self._get_session()
        if not self.enabled or not session:
            return None

        # Rate limiting
        current_time = time.time()
        if current_time - self.last_call < self.rate_limit:
            return None
        self.last_call = current_time

        context_str = "\n".join([f"[{c['timestamp']}] {c['log']}" for c in context[-5:]])

        prompt = f"""You are a cybersecurity expert analyzing system logs for threats.
Analyze the following log entry and recent context for security threats, anomalies, or attack patterns.

Recent Context:
{context_str}

Current Log Entry:
{log_line}

Provide a JSON response with this exact structure:
{{
    "is_threat": boolean,
    "threat_type": "none" | "malware" | "intrusion" | "anomaly" | "reconnaissance" | "data_exfiltration",
    "confidence": 0.0-1.0,
    "description": "brief explanation",
    "recommended_action": "specific remediation step",
    "indicators": ["list", "of", "ioc", "indicators"]
}}

Respond ONLY with the JSON object, no other text."""

        try:
            async with session.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    try:
                        response_text = result.get('response', '')
                        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                        if json_match:
                            return json.loads(json_match.group())
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse AI response as JSON")
                else:
                    logger.warning(f"Ollama API returned status {response.status}")
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")

        return None

    async def close(self):
        if self.session:
            await self.session.close()
