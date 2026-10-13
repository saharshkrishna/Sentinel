"""
limitations.py - Documents all known system limitations of the Windows IDS.
"""

LIMITATIONS = {
    "System-Level": [
        "Some event logs do not contain process name or PID information.",
        "Mapping log events to running processes may not always be accurate.",
        "Security/audit log access requires Administrator (Windows) or root (Linux) privileges.",
    ],
    "Permission Constraints": [
        "Elevated privileges are required to terminate or suspend unauthorized processes.",
        "Critical system processes (lsass.exe, csrss.exe on Windows; systemd, init on Linux) are protected and cannot be controlled.",
        "Some system services cannot be stopped programmatically without root/Admin rights.",
    ],
    "Detection Accuracy": [
        "Rule-based detection may produce false positives for benign events.",
        "AI model (deepseek-coder) may misclassify ambiguous or unusual log entries.",
        "Offline log analysis does not include live process context.",
    ],
    "Performance": [
        "High log volume during events (e.g., Windows Updates) may delay real-time analysis.",
        "Frequent psutil process lookups can increase CPU usage under heavy load.",
        "The AI engine (Ollama) adds latency per event; cache helps but the first query is slow.",
    ],
    "OS Restrictions": [
        "Process suspension (SIGSTOP equivalent) may not work for all applications on Windows.",
        "UWP (Store) apps and Windows-sandboxed processes cannot be controlled via standard APIs.",
        "Flood detection thresholds are configurable but require tuning per environment.",
    ],
}


def get_limitations_text() -> str:
    """Return all limitations as a formatted multi-line string for UI display."""
    lines = []
    for category, items in LIMITATIONS.items():
        lines.append(f"{'━' * 50}")
        lines.append(f"  {category}")
        lines.append(f"{'━' * 50}")
        for item in items:
            lines.append(f"  • {item}")
        lines.append("")
    return "\n".join(lines)
