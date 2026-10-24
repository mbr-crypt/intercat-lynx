"""
Initial data import, started from the setup assistant.

Runs in a background thread of the API process and writes its progress into
the database (``app_settings`` key ``import.status``), so the browser can poll
it. The progress survives a page reload. If the server is restarted during an
import, the state is reported as "interrupted" and the import can be started
again (already imported CVEs are simply updated).

Phases: NVD (the CVE database of the US NIST) -> CISA KEV (list of
vulnerabilities that are being exploited right now) -> statistics -> product
catalog.

Resume: after every saved NVD page the job stores where it stands (the
"checkpoint": time window and position in the list) in the status. If the import
is interrupted or fails, ``can_resume`` is set and a new run can continue from
there instead of starting at page 1.

Live display: while the import runs, a second thread writes a heartbeat every
few seconds. A status that has not received a heartbeat for HEARTBEAT_TIMEOUT
belongs to a process that no longer exists and is shown as "interrupted". The
status also carries a short event log ("Seite 2 von 3 gespeichert", ...) so the
browser can show what is happening right now.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from . import settings_service

logger = logging.getLogger(__name__)

STATUS_KEY = "import.status"
# The heartbeat is written every HEARTBEAT_INTERVAL seconds, independent of what
# the import is doing (waiting for the NVD, saving, calculating statistics).
# Without a sign of life for HEARTBEAT_TIMEOUT the import counts as dead.
HEARTBEAT_INTERVAL = 5.0
HEARTBEAT_TIMEOUT = timedelta(seconds=90)
# Progress is written to the database at most this often (seconds)
PROGRESS_WRITE_INTERVAL = 2.0
LOG_LIMIT = 15
# The remaining time is estimated only after this much work and time (before that
# the rate is too uncertain)
ETA_MIN_SECONDS = 30.0
ETA_MIN_ITEMS = 50

PHASES = ("nvd", "cisa_kev", "stats", "catalog")

_lock = threading.Lock()
_running = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _is_alive(status: dict) -> bool:
    """A running status with a recent heartbeat belongs to a living import."""
    beat = _parse(status.get("heartbeat")) or _parse(status.get("started_at"))
    return beat is not None and _now() - beat <= HEARTBEAT_TIMEOUT


def read_status(db: Session) -> dict:
    raw = settings_service.get(db, STATUS_KEY)
    if not raw:
        return {"state": "idle"}
    status = json.loads(raw)
    now = _now()
    if status.get("state") == "running" and not _running and not _is_alive(status):
        # Only the process that runs the import knows `_running`; every other
        # process judges by the heartbeat in the database.
        status["state"] = "interrupted"
        status["message"] = (
            "Der Import wurde unterbrochen (Neustart des Servers?). "
            "Er kann erneut gestartet werden."
        )
    started = _parse(status.get("started_at"))
    if started:
        end = _parse(status.get("finished_at")) if status.get("state") != "running" else now
        if status.get("state") == "interrupted":
            end = _parse(status.get("heartbeat")) or now
        status["elapsed_seconds"] = max(0, int(((end or now) - started).total_seconds()))
    beat = _parse(status.get("heartbeat"))
    if beat and status.get("state") == "running":
        status["seconds_since_heartbeat"] = max(0, int((now - beat).total_seconds()))
    status["phases"] = list(PHASES)
    # Also after the NVD phase: the last checkpoint then points to the end of the list
    # and a resumed run goes straight on to the later phases
    status["can_resume"] = bool(status.get("state") in ("interrupted", "error") and status.get("checkpoint"))
    return status


def resume_point(db: Session) -> Optional[dict]:
    """Mode, days and checkpoint of an interrupted import, or None."""
    status = read_status(db)
    if not status.get("can_resume"):
        return None
    return {
        "mode": status.get("mode"),
        "days": status.get("days") or 30,
        "checkpoint": status["checkpoint"],
    }


class _Reporter:
    """Holds the status of one import run and writes it to the database.

    Called from several threads (the import itself, the heartbeat), therefore
    every access goes through one lock.
    """

    def __init__(self, session_factory: Callable[[], Session], status: dict):
        self._factory = session_factory
        self._status = status
        self._lock = threading.Lock()
        self._closed = False
        self._last_write = 0.0
        self._eta_base: Optional[tuple] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._status.setdefault("log", [])

    # -- writing -----------------------------------------------------------
    def _flush(self) -> None:
        self._status["heartbeat"] = _now().isoformat()
        db = self._factory()
        try:
            settings_service.set_value(db, STATUS_KEY, json.dumps(self._status))
        finally:
            db.close()
        self._last_write = time.monotonic()

    def write(self) -> None:
        with self._lock:
            if not self._closed:
                self._flush()

    def update(self, **fields) -> None:
        """Change fields and write at once (phase changes, rare)."""
        with self._lock:
            if "phase" in fields:
                self._status.pop("eta_seconds", None)
            self._status.update(fields)
            if not self._closed:
                self._flush()

    def progress(self, done: int, total: int, note: Optional[str] = None) -> None:
        """Change the counter; written at most every PROGRESS_WRITE_INTERVAL."""
        with self._lock:
            self._status["processed"], self._status["total"] = done, total
            if note:
                self._status["detail"] = note
            self._estimate(done, total)
            if not self._closed and time.monotonic() - self._last_write >= PROGRESS_WRITE_INTERVAL:
                self._flush()

    def _estimate(self, done: int, total: Optional[int]) -> None:
        """Remaining time from the speed since this run began (called under the lock)."""
        now = time.monotonic()
        if self._eta_base is None or done < self._eta_base[1]:
            self._eta_base = (now, done)
            return
        base_time, base_done = self._eta_base
        if not total or done >= total:
            self._status.pop("eta_seconds", None)
            return
        if now - base_time >= ETA_MIN_SECONDS and done - base_done >= ETA_MIN_ITEMS:
            rate = (done - base_done) / (now - base_time)
            self._status["eta_seconds"] = int((total - done) / rate)

    def checkpoint(self, point: dict) -> None:
        """Remember where to continue if this run is interrupted."""
        with self._lock:
            self._status["checkpoint"] = point
            if not self._closed:
                self._flush()

    def event(self, text: str) -> None:
        with self._lock:
            log = self._status["log"]
            log.append({"t": _now().isoformat(), "text": text})
            del log[:-LOG_LIMIT]
            self._status["detail"] = text
            if not self._closed:
                self._flush()

    # -- heartbeat ---------------------------------------------------------
    def _beat(self) -> None:
        while not self._stop.wait(HEARTBEAT_INTERVAL):
            try:
                self.write()
            except Exception as e:  # noqa: BLE001 - a lost beat must not kill the import
                logger.warning("Import heartbeat failed: %s: %s", type(e).__name__, e)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._beat, name="lynx-import-heartbeat", daemon=True)
        self._thread.start()

    def finish(self, **fields) -> dict:
        """Stop the heartbeat and write the final status."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        with self._lock:
            self._status.update(fields)
            self._flush()
            self._closed = True
            return dict(self._status)


def run_import(
    session_factory: Callable[[], Session],
    mode: str,
    days: int = 30,
    nvd_factory: Optional[Callable] = None,
    kev_factory: Optional[Callable] = None,
    stats_refresh: Optional[Callable[[Session], bool]] = None,
    resume: Optional[dict] = None,
) -> dict:
    """Synchronous import. Returns the final status (also persisted).

    ``resume`` is the checkpoint of an interrupted run; the NVD phase then
    continues there.
    """
    status = {
        "state": "running",
        "mode": mode,
        "days": days,
        "phase": "nvd",
        "processed": (resume or {}).get("start_index", 0),
        "total": None,
        "started_at": _now().isoformat(),
        "message": "CVE-Daten werden von der NVD geladen",
        "log": [],
    }
    if resume:
        status["checkpoint"] = resume
        status["resumed"] = True
    reporter = _Reporter(session_factory, status)
    reporter.write()
    reporter.start()

    try:
        if mode not in ("recent", "full"):
            raise ValueError(f"unknown import mode {mode!r}")

        if nvd_factory is None:
            from .nvd_complete_service import get_nvd_service as nvd_factory
        if kev_factory is None:
            from .cisa_kev_service import get_cisa_kev_service as kev_factory
        if stats_refresh is None:
            from .stats_cache_service import refresh_stats_cache as stats_refresh

        reporter.event("Import wird fortgesetzt" if resume else "Import gestartet")
        nvd = nvd_factory()
        nvd.progress_callback = reporter.progress
        nvd.event_callback = reporter.event
        nvd.checkpoint_callback = reporter.checkpoint
        extra = {"resume": resume} if resume else {}
        if mode == "full":
            # No checkpoint file: the resume point lives in the status
            nvd.fetch_all_cves(checkpoint_file=None, **extra)
        else:
            nvd.fetch_recent_cves(days=days, **extra)

        reporter.update(
            phase="cisa_kev",
            detail=None,
            message="Aktiv ausgenutzte Lücken (CISA KEV) werden geladen",
        )
        reporter.event("CVE-Daten geladen, CISA KEV wird abgefragt")
        db = session_factory()
        try:
            kev = kev_factory()
            kev.event_callback = reporter.event
            result = kev.update_exploited_vulnerabilities(db)
        finally:
            db.close()
        if isinstance(result, dict):
            if result.get("status") == "success":
                reporter.event(
                    f"CISA KEV: {result.get('updated', 0)} CVEs als aktiv ausgenutzt markiert, "
                    f"davon {result.get('created', 0)} neu angelegt"
                )
            else:
                reporter.event("CISA KEV konnte nicht abgefragt werden (nicht kritisch, die tägliche Aufgabe versucht es erneut)")

        reporter.update(phase="stats", message="Statistik wird berechnet")
        reporter.event("Statistik wird berechnet")
        db = session_factory()
        try:
            stats_refresh(db)
        finally:
            db.close()

        # The product picker searches this list; a failure must not fail the import
        reporter.update(phase="catalog", message="Produktkatalog wird aufgebaut")
        reporter.event("Produktkatalog wird aufgebaut")
        db = session_factory()
        try:
            from .watchlist_service import rebuild_catalog

            rebuild_catalog(db)
        except Exception as e:  # noqa: BLE001
            logger.warning("Product catalog rebuild failed: %s: %s", type(e).__name__, e)
            reporter.event("Produktkatalog konnte nicht aufgebaut werden (nicht kritisch)")
        finally:
            db.close()

        reporter.event("Import abgeschlossen")
        return reporter.finish(
            state="done",
            phase="done",
            detail=None,
            message="Import abgeschlossen",
            finished_at=_now().isoformat(),
        )
    except Exception as e:
        logger.error("Import failed: %s: %s", type(e).__name__, e)
        reporter.event(f"Fehler: {type(e).__name__}")
        return reporter.finish(
            state="error",
            message=f"Import fehlgeschlagen: {type(e).__name__}: {e}",
            finished_at=_now().isoformat(),
        )


def start_in_background(
    session_factory: Callable[[], Session],
    mode: str,
    days: int,
    resume: Optional[dict] = None,
) -> bool:
    """Start the import thread. False if one is already running."""
    global _running
    with _lock:
        if _running:
            return False
        # Another process of the API server may already run it (the thread
        # lives in ONE process, the flag above only knows its own)
        db = session_factory()
        try:
            raw = settings_service.get(db, STATUS_KEY)
        finally:
            db.close()
        if raw:
            current = json.loads(raw)
            if current.get("state") == "running" and _is_alive(current):
                return False
        _running = True

    def target():
        global _running
        try:
            run_import(session_factory, mode, days, resume=resume)
        finally:
            _running = False

    threading.Thread(target=target, name="lynx-import", daemon=True).start()
    return True
