"""
aegis.session_logger — Persistent operational and engineering session logging.

Provides structured JSONL and plaintext session logging for all AEGIS operations,
including rule compilation, correlation runs, graph generations, and manual
analyst notes.
"""

from __future__ import annotations

import getpass
import json
import logging
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path("logs")
SESSION_LOG_FILE = DEFAULT_LOG_DIR / "aegis_session.log"
SESSION_JSONL_FILE = DEFAULT_LOG_DIR / "aegis_session.jsonl"


class SessionLogger:
    """Manages appending and querying session log records."""

    def __init__(self, log_dir: Path | str = DEFAULT_LOG_DIR) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "aegis_session.log"
        self.jsonl_file = self.log_dir / "aegis_session.jsonl"

    def log_event(
        self,
        action: str,
        status: str = "SUCCESS",
        details: dict[str, Any] | None = None,
        duration_s: float | None = None,
        user: str | None = None,
    ) -> dict[str, Any]:
        """Record an operational event in the session log.

        Parameters
        ----------
        action:
            High-level action name (e.g. 'rules_compile', 'correlate_run', 'analyst_note').
        status:
            Outcome status ('SUCCESS', 'FAILED', 'WARNING', 'NOTE').
        details:
            Arbitrary key-value metadata for the event.
        duration_s:
            Execution duration in seconds if timed.
        user:
            Operator username; defaults to current OS user.

        Returns
        -------
        dict[str, Any]
            The written log record.
        """
        now = datetime.now(timezone.utc)
        record: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "action": action,
            "status": status.upper(),
            "user": user or getpass.getuser(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "duration_seconds": round(duration_s, 4) if duration_s is not None else None,
            "details": details or {},
        }

        # 1. Append to JSONL for programmatic querying
        with self.jsonl_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

        # 2. Append formatted plaintext line to human-readable log
        dur_str = f" ({duration_s:.3f}s)" if duration_s is not None else ""
        details_str = f" | {json.dumps(details, default=str)}" if details else ""
        log_line = (
            f"[{record['timestamp']}] [{record['status']}] {record['action'].upper()} "
            f"by {record['user']}@{record['hostname']}{dur_str}{details_str}\n"
        )
        with self.log_file.open("a", encoding="utf-8") as f:
            f.write(log_line)

        return record

    def add_note(self, note: str, author: str | None = None) -> dict[str, Any]:
        """Add an analyst engineering note to the session log."""
        return self.log_event(
            action="analyst_note",
            status="NOTE",
            details={"message": note},
            user=author,
        )

    def read_recent(self, limit: int = 15) -> list[dict[str, Any]]:
        """Read the last N session records from the JSONL log."""
        if not self.jsonl_file.exists():
            return []

        records = []
        with self.jsonl_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records[-limit:]
