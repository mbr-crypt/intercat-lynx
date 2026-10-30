"""
BSI CERT-Bund warnings (WID) from the CSAF feed.

The BSI publishes its warnings as CSAF 2.0 documents (JSON). The provider
metadata (https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json)
lists the feeds in ROLIE format ("a list of documents with their change date").
We read the public feed of the warning service (TLP:WHITE) only; the GREEN feeds
are not meant for the public and are never touched.

What is kept: number, title, severity, dates, CVE numbers, a short list of
affected products and the link to the original. The text of a warning stays at
the BSI (nothing is mirrored), every entry links back to the source.

Safety rules for the download:
- only https and only the host ``wid.cert-bund.de``, also for every link inside
  the feed and for redirects (the feed content is data, it must not be able to
  point us to another server)
- size limit per response, timeouts, a pause between documents
- reading the feed conditionally (ETag), so an unchanged feed costs almost nothing
"""

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from sqlalchemy.orm import Session

from ..models import BsiAdvisory, BsiAdvisoryCve
from . import settings_service

logger = logging.getLogger(__name__)

ALLOWED_HOST = "wid.cert-bund.de"
FEED_URL = "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json"
PORTAL_URL = "https://wid.cert-bund.de/portal/wid/securityadvisory?name="
USER_AGENT = "InterCat-Lynx/0.1 (vulnerability management; reads the public BSI CSAF feed)"

# first run: how far back warnings are taken over
INITIAL_DAYS = 60
# later runs start this long before the last successful run (changes to old entries)
OVERLAP = timedelta(days=2)
# documents loaded per run; the rest follows with the next run
MAX_DOCS_PER_RUN = 400
PAUSE_BETWEEN_DOCS = 0.1  # seconds
FEED_MAX_BYTES = 64 * 1024 * 1024
DOC_MAX_BYTES = 8 * 1024 * 1024
MAX_PRODUCTS = 15
MAX_REDIRECTS = 3

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = {
    "critical": "kritisch",
    "kritisch": "kritisch",
    "high": "hoch",
    "hoch": "hoch",
    "medium": "mittel",
    "mittel": "mittel",
    "low": "niedrig",
    "niedrig": "niedrig",
}

KEY_ENABLED = "bsi.enabled"
KEY_LAST_SYNC = "bsi.last_sync"
KEY_ETAG = "bsi.feed_etag"

# (status, body, headers); the fetcher is replaceable for tests
Fetcher = Callable[[str, Dict[str, str], int], Tuple[int, bytes, Dict[str, str]]]


class BsiError(Exception):
    """Download or format problem. The message never contains response content."""


# --------------------------------------------------------------------------
# switch
# --------------------------------------------------------------------------


def is_enabled(db: Session) -> bool:
    """Database > environment variable BSI_ENABLED > default (on)."""
    value = settings_service.get(db, KEY_ENABLED)
    if value in (None, ""):
        value = os.getenv("BSI_ENABLED", "true")
    return str(value).lower() != "false"


# --------------------------------------------------------------------------
# download
# --------------------------------------------------------------------------


def _check_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST or parsed.port not in (None, 443):
        raise BsiError("Adresse außerhalb von wid.cert-bund.de")
    return url


def http_get(url: str, headers: Dict[str, str], max_bytes: int) -> Tuple[int, bytes, Dict[str, str]]:
    """GET with host check on every redirect and a size limit."""
    for _ in range(MAX_REDIRECTS + 1):
        _check_url(url)
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json", **headers},
            timeout=(10, 60),
            stream=True,
            allow_redirects=False,
        )
        try:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                url = requests.compat.urljoin(url, location)
                continue
            if response.status_code == 304:
                return 304, b"", dict(response.headers)
            if response.status_code != 200:
                return response.status_code, b"", dict(response.headers)
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise BsiError("Antwort zu groß")
            return 200, bytes(body), dict(response.headers)
        finally:
            response.close()
    raise BsiError("Zu viele Weiterleitungen")


def _json(body: bytes):
    import json

    try:
        return json.loads(body)
    except ValueError as e:
        raise BsiError("Antwort ist kein gültiges JSON") from e


# --------------------------------------------------------------------------
# parsing (pure functions)
# --------------------------------------------------------------------------


def parse_time(value) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """SQLite returns naive datetimes; treat them as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def parse_feed(feed: dict) -> List[dict]:
    """ROLIE feed -> [{"url", "updated"}], newest first. Unusable entries are dropped."""
    entries = []
    raw = ((feed or {}).get("feed") or {}).get("entry") or []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        url = (entry.get("content") or {}).get("src")
        if not url:
            for link in entry.get("link") or []:
                if isinstance(link, dict) and link.get("rel") == "self" and link.get("href"):
                    url = link["href"]
                    break
        updated = parse_time(entry.get("updated")) or parse_time(entry.get("published"))
        if not isinstance(url, str) or updated is None:
            continue
        try:
            _check_url(url)
        except BsiError:
            logger.warning("BSI feed entry with a foreign address skipped")
            continue
        entries.append({"url": url, "updated": updated})
    entries.sort(key=lambda e: e["updated"], reverse=True)
    return entries


def _collect_products(branches, vendor: str, found: List[str]) -> None:
    for branch in branches or []:
        if not isinstance(branch, dict):
            continue
        category = branch.get("category")
        name = str(branch.get("name") or "").strip()
        child_vendor = vendor
        if category == "vendor" and name:
            child_vendor = name
        elif category == "product_name" and name:
            label = name if (not vendor or vendor.lower() in name.lower()) else f"{vendor} {name}"
            if label not in found:
                found.append(label)
        _collect_products(branch.get("branches"), child_vendor, found)


def portal_url(advisory_id: str) -> str:
    """Address of the warning on the BSI portal (the portal writes the number without the ``-W-``)."""
    return PORTAL_URL + advisory_id.replace("-W-", "-")


def parse_advisory(doc: dict, csaf_url: str) -> dict:
    """CSAF 2.0 document -> the fields we keep. Raises BsiError for unusable documents."""
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        raise BsiError("Kein CSAF-Dokument")
    meta = doc["document"]
    tracking = meta.get("tracking") or {}
    advisory_id = str(tracking.get("id") or "").strip().upper()
    title = str(meta.get("title") or "").strip()
    if not advisory_id or not title or len(advisory_id) > 60:
        raise BsiError("Nummer oder Titel fehlt")

    severity_text = str((meta.get("aggregate_severity") or {}).get("text") or "").strip().lower()
    cves: List[str] = []
    for vulnerability in doc.get("vulnerabilities") or []:
        if isinstance(vulnerability, dict):
            cve = str(vulnerability.get("cve") or "").strip().upper()
            if CVE_RE.match(cve) and cve not in cves:
                cves.append(cve)

    products: List[str] = []
    tree = doc.get("product_tree") or {}
    _collect_products(tree.get("branches"), "", products)

    return {
        "advisory_id": advisory_id,
        "title": title[:500],
        "severity": SEVERITIES.get(severity_text),
        "published_at": parse_time(tracking.get("initial_release_date")),
        "updated_at": parse_time(tracking.get("current_release_date")),
        "url": portal_url(advisory_id),
        "csaf_url": csaf_url[:500],
        "products": [p[:120] for p in products[:MAX_PRODUCTS]],
        "cves": cves,
    }


# --------------------------------------------------------------------------
# storing
# --------------------------------------------------------------------------


def upsert(db: Session, data: dict, feed_updated_at: Optional[datetime] = None) -> str:
    """Insert or update one warning. Returns "new" or "updated"."""
    row = db.query(BsiAdvisory).filter(BsiAdvisory.advisory_id == data["advisory_id"]).first()
    result = "updated"
    if row is None:
        row = BsiAdvisory(advisory_id=data["advisory_id"])
        db.add(row)
        result = "new"
    row.title = data["title"]
    row.severity = data["severity"]
    row.published_at = data["published_at"]
    row.updated_at = data["updated_at"]
    row.url = data["url"]
    row.csaf_url = data["csaf_url"]
    row.feed_updated_at = feed_updated_at
    row.products = data["products"]
    row.cve_count = len(data["cves"])
    db.flush()
    existing = {c.cve_id: c for c in row.cves}
    for cve_id, link in existing.items():
        if cve_id not in data["cves"]:
            db.delete(link)
    for cve_id in data["cves"]:
        if cve_id not in existing:
            db.add(BsiAdvisoryCve(advisory_id=row.id, cve_id=cve_id))
    return result


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def run(
    db: Session,
    fetcher: Optional[Fetcher] = None,
    now: Optional[datetime] = None,
    pause: float = PAUSE_BETWEEN_DOCS,
) -> dict:
    """
    Fetch new and changed warnings. Returns counters (a dict for the task report).
    Raises BsiError when the feed cannot be read at all.
    """
    fetch = fetcher or http_get
    now = now or datetime.now(timezone.utc)

    if not is_enabled(db):
        return {"status": "success", "disabled": True, "new": 0, "updated": 0}

    last_sync = parse_time(settings_service.get(db, KEY_LAST_SYNC))
    cutoff = (last_sync - OVERLAP) if last_sync else (now - timedelta(days=INITIAL_DAYS))

    headers: Dict[str, str] = {}
    etag = settings_service.get(db, KEY_ETAG)
    if last_sync and etag:
        headers["If-None-Match"] = etag
    status, body, response_headers = fetch(FEED_URL, headers, FEED_MAX_BYTES)
    if status == 304:
        settings_service.set_value(db, KEY_LAST_SYNC, now.isoformat())
        return {"status": "success", "new": 0, "updated": 0, "unchanged": 1}
    if status != 200:
        raise BsiError(f"Feed nicht abrufbar (HTTP {status})")

    entries = [e for e in parse_feed(_json(body)) if e["updated"] >= cutoff]

    # skip what is already stored in this version
    known: Dict[str, Optional[datetime]] = {}
    urls = [e["url"] for e in entries]
    for start in range(0, len(urls), 500):
        for row in (
            db.query(BsiAdvisory.csaf_url, BsiAdvisory.feed_updated_at)
            .filter(BsiAdvisory.csaf_url.in_(urls[start : start + 500]))
            .all()
        ):
            known[row[0]] = _aware(row[1])
    todo = [e for e in entries if not (known.get(e["url"]) and known[e["url"]] >= e["updated"])]
    capped = len(todo) > MAX_DOCS_PER_RUN
    todo = todo[:MAX_DOCS_PER_RUN]

    counts = {"new": 0, "updated": 0, "failed": 0}
    for number, entry in enumerate(todo, start=1):
        try:
            doc_status, doc_body, _ = fetch(entry["url"], {}, DOC_MAX_BYTES)
            if doc_status != 200:
                raise BsiError(f"HTTP {doc_status}")
            data = parse_advisory(_json(doc_body), entry["url"])
            counts[upsert(db, data, entry["updated"])] += 1
        except Exception as e:  # noqa: BLE001 - one bad document must not stop the run
            db.rollback()
            counts["failed"] += 1
            logger.warning("BSI document skipped (%s)", type(e).__name__)
        if number % 50 == 0:
            db.commit()
        if pause:
            time.sleep(pause)
    db.commit()

    # Only move the starting point forward when everything was taken over;
    # otherwise the next run continues (known documents are skipped).
    if not capped and counts["failed"] == 0:
        settings_service.set_value(db, KEY_LAST_SYNC, now.isoformat())
        etag_new = response_headers.get("ETag") or response_headers.get("etag")
        if etag_new:
            settings_service.set_value(db, KEY_ETAG, etag_new)
    logger.info("BSI CSAF: %s", counts)
    return {"status": "success", **counts, "remaining": 1 if capped else 0}


def status(db: Session) -> dict:
    """For the administration: switch, last run, number of stored warnings."""
    return {
        "enabled": is_enabled(db),
        "last_sync": settings_service.get(db, KEY_LAST_SYNC),
        "advisories": db.query(BsiAdvisory).count(),
        "feed": FEED_URL,
    }
