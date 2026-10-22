"""
Initial data import, started from the setup assistant.

Runs in a background thread of the API process and writes its progress into
the database (``app_settings`` key ``import.status``), so the browser can poll
it. The progress survives a page reload. If the server is restarted during an
import, the state is reported as "interrupted" and the import can be started
again (already imported CVEs are simply updated).

Phases: NVD (the CVE database of the US NIST) -> CISA KEV (list of
vulnerabilities that are being exploited right now) -> statistics.
"""

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from . import settings_service

logger = logging.getLogger(__name__)

STATUS_KEY = "import.status"
HEARTBEAT_TIMEOUT = timedelta(minutes=3)

_lock = threading.Lock()
_running = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def read_status(db: Session) -> dict:
    raw = settings_service.get(db, STATUS_KEY)
    if not raw:
        return {"state": "idle"}
    status = json.loads(raw)
    if status.get("state") == "running":
        beat = datetime.fromisoformat(status.get("heartbeat", status["started_at"]))
        if _now() - beat > HEARTBEAT_TIMEOUT and not _running:
            status["state"] = "interrupted"
            status["message"] = (
                "Der Import wurde unterbrochen (Neustart des Servers?). "
                "Er kann erneut gestartet werden."
            )
    return status


def _write(session_factory: Callable[[], Session], status: dict) -> None:
    status["heartbeat"] = _now().isoformat()
    db = session_factory()
    try:
        settings_service.set_value(db, STATUS_KEY, json.dumps(status))
    finally:
        db.close()


def run_import(
    session_factory: Callable[[], Session],
    mode: str,
    days: int = 30,
    nvd_factory: Optional[Callable] = None,
    kev_factory: Optional[Callable] = None,
    stats_refresh: Optional[Callable[[Session], bool]] = None,
) -> dict:
    """Synchronous import. Returns the final status (also persisted)."""
    status = {
        "state": "running",
        "mode": mode,
        "phase": "nvd",
        "processed": 0,
        "total": None,
        "started_at": _now().isoformat(),
        "message": "CVE-Daten werden von der NVD geladen",
    }
    _write(session_factory, status)

    try:
        if mode not in ("recent", "full"):
            raise ValueError(f"unknown import mode {mode!r}")

        if nvd_factory is None:
            from .nvd_complete_service import get_nvd_service as nvd_factory
        if kev_factory is None:
            from .cisa_kev_service import get_cisa_kev_service as kev_factory
        if stats_refresh is None:
            from .stats_cache_service import refresh_stats_cache as stats_refresh

        nvd = nvd_factory()

        def on_progress(done: int, total: int) -> None:
            status["processed"], status["total"] = done, total
            _write(session_factory, status)

        nvd.progress_callback = on_progress
        if mode == "full":
            nvd.fetch_all_cves()
        else:
            nvd.fetch_recent_cves(days=days)

        status.update(phase="cisa_kev", message="Aktiv ausgenutzte Lücken (CISA KEV) werden geladen")
        _write(session_factory, status)
        db = session_factory()
        try:
            kev_factory().update_exploited_vulnerabilities(db)
        finally:
            db.close()

        status.update(phase="stats", message="Statistik wird berechnet")
        _write(session_factory, status)
        db = session_factory()
        try:
            stats_refresh(db)
        finally:
            db.close()

        status.update(
            state="done",
            phase="done",
            message="Import abgeschlossen",
            finished_at=_now().isoformat(),
        )
    except Exception as e:
        logger.error("Import failed: %s: %s", type(e).__name__, e)
        status.update(
            state="error",
            message=f"Import fehlgeschlagen: {type(e).__name__}: {e}",
            finished_at=_now().isoformat(),
        )

    _write(session_factory, status)
    return status


def start_in_background(session_factory: Callable[[], Session], mode: str, days: int) -> bool:
    """Start the import thread. False if one is already running."""
    global _running
    with _lock:
        if _running:
            return False
        _running = True

    def target():
        global _running
        try:
            run_import(session_factory, mode, days)
        finally:
            _running = False

    threading.Thread(target=target, name="lynx-import", daemon=True).start()
    return True
