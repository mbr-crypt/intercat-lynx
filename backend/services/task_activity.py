"""
Report of the scheduled background tasks (Celery) for the administration.

The tasks run in the Celery worker, a different container than the API. The
only place both sides share is the database, so every run writes a small status
entry into ``app_settings`` (key ``task.<id>``): when it started, whether it is
still running, how it ended. The page "Administration -> Daten" lists them.

Reporting must never break a task: every database error in here is only logged.
"""

import functools
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ..database import SessionLocal
from . import settings_service

logger = logging.getLogger(__name__)

KEY_PREFIX = "task."
# A run that says "running" for longer than this was killed (worker restart)
STALE_AFTER = timedelta(hours=2)

# id -> (title shown to the administrator, schedule in words). Same ids as the
# entries in celery_app.beat_schedule.
SCHEDULED: Dict[str, tuple] = {
    "fetch-nvd-recent": ("NVD: neue und geänderte CVEs holen", "alle 6 Stunden"),
    "fetch-cisa-kev": ("CISA KEV: aktiv ausgenutzte Lücken abgleichen", "täglich 09:00 UTC"),
    "send-product-alerts": ("Benachrichtigungen zu beobachteten Produkten", "alle 10 Minuten"),
    "rebuild-product-catalog": ("Produktkatalog neu zählen", "täglich 03:30 UTC"),
    "refresh-stats-cache": ("Statistik-Zwischenspeicher aktualisieren", "alle 5 Minuten"),
    "process-new-cves": ("Neue CVEs mit dem Sprachmodell auswerten", "alle 10 Minuten"),
    "fetch-news-articles": ("Nachrichtenartikel abrufen", "alle 30 Minuten"),
    "process-news-with-llm": ("Nachrichten mit dem Sprachmodell auswerten", "alle 15 Minuten"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _write(task_id: str, entry: dict) -> None:
    db = None
    try:
        db = SessionLocal()
        settings_service.set_value(db, KEY_PREFIX + task_id, json.dumps(entry))
    except Exception as e:  # noqa: BLE001 - reporting must not break the task
        logger.warning("Task report for %s failed: %s", task_id, type(e).__name__)
        try:
            if db is not None:
                db.rollback()
        except Exception:  # noqa: BLE001
            pass
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:  # noqa: BLE001
                pass


def _summary(result) -> tuple:
    """(state, short text) from what a task returned."""
    if not isinstance(result, dict):
        return "ok", ""
    if result.get("status") == "error":
        return "error", str(result.get("message") or "Fehler")[:200]
    numbers = [
        f"{k.replace('_', ' ')}: {v}"
        for k, v in result.items()
        if isinstance(v, int) and not isinstance(v, bool)
    ]
    return "ok", ", ".join(numbers[:4])


def tracked(task_id: str) -> Callable:
    """Decorator for a Celery task function: records start and outcome."""

    def decorate(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            started = _now().isoformat()
            _write(task_id, {"state": "running", "started_at": started})
            try:
                result = fn(*args, **kwargs)
            except BaseException as e:  # includes Celery's Retry; always re-raised
                _write(
                    task_id,
                    {
                        "state": "error",
                        "started_at": started,
                        "finished_at": _now().isoformat(),
                        "message": "wird wiederholt" if type(e).__name__ == "Retry" else type(e).__name__,
                    },
                )
                raise
            state, text = _summary(result)
            _write(
                task_id,
                {
                    "state": state,
                    "started_at": started,
                    "finished_at": _now().isoformat(),
                    "message": text,
                },
            )
            return result

        return wrapper

    return decorate


def read_all(db: Session) -> List[dict]:
    """Last run of every scheduled task, in the order of SCHEDULED."""
    out = []
    for task_id, (title, schedule) in SCHEDULED.items():
        raw = settings_service.get(db, KEY_PREFIX + task_id)
        entry: dict = {"state": "never"}
        if raw:
            try:
                entry = json.loads(raw)
            except ValueError:
                entry = {"state": "never"}
        if entry.get("state") == "running":
            try:
                started = datetime.fromisoformat(entry.get("started_at", ""))
                if _now() - started > STALE_AFTER:
                    entry = {**entry, "state": "interrupted"}
            except ValueError:
                entry = {**entry, "state": "interrupted"}
        out.append({"id": task_id, "title": title, "schedule": schedule, **entry})
    return out
