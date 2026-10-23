"""
Product selection ("watchlist"): which CVEs concern the products a user follows.

A followed product is a vendor/product pair in CPE spelling (lower case,
underscores): ``fortinet`` / ``fortios``. Leaving the product empty follows the
whole vendor.

How a CVE is matched to a followed product
------------------------------------------
1. **CPE**: NVD lists the affected products as CPE strings such as
   ``cpe:2.3:a:fortinet:fortios:7.0.1:*:*...``. If vendor and product appear
   in one of them, the CVE matches. This is the precise way.
2. **Names**: for fresh CVEs NVD has often not analysed yet, so there are no
   CPE strings. Then the vendor and product names the CNA reported
   (``vendors`` / ``products`` columns) are compared instead.

Both paths exist twice: as an SQL condition (to find CVEs in the database) and
as a Python check (to say *which* followed product matched a CVE). The tests
keep the two in agreement.
"""

import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import Text, and_, cast, func, or_
from sqlalchemy.orm import Session

from ..models import ProductCatalog, Vulnerability, WatchedProduct

logger = logging.getLogger(__name__)

# Ascending, so "at least HIGH" is SEVERITIES[index("HIGH"):]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

MAX_WATCHES_PER_USER = 200


# --- names ----------------------------------------------------------------


def slug(value: Optional[str]) -> str:
    """CPE spelling: lower case, spaces become underscores."""
    return (value or "").strip().lower().replace(" ", "_")


def label(value: Optional[str]) -> str:
    """Readable spelling (the same one the importer stores in ``vendors``)."""
    return (value or "").replace("_", " ").title()


def watch_label(vendor: str, product: Optional[str]) -> str:
    if product:
        return f"{label(vendor)} {label(product)}"
    return f"{label(vendor)} (all products)"


def cpe_pair(cpe: str) -> Optional[Tuple[str, str]]:
    """``cpe:2.3:a:vendor:product:...`` -> (vendor, product), or None."""
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0].lower() != "cpe":
        return None
    vendor, product = parts[3].lower(), parts[4].lower()
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return vendor, product


def severities_from(minimum: Optional[str]) -> Optional[List[str]]:
    if not minimum:
        return None
    minimum = minimum.upper()
    if minimum not in SEVERITIES:
        return None
    return SEVERITIES[SEVERITIES.index(minimum) :]


# --- catalog ---------------------------------------------------------------


def vulnerability_pairs(vuln) -> set:
    """All (vendor, product) pairs a CVE is known to affect."""
    pairs = set()
    for cpe in vuln.affected_products or []:
        pair = cpe_pair(cpe) if isinstance(cpe, str) else None
        if pair:
            pairs.add(pair)
    if not pairs:
        vendors = [slug(v) for v in (vuln.vendors or [])]
        products = [slug(p) for p in (vuln.products or [])]
        # Without CPE the products cannot be tied to a vendor unless there is
        # exactly one vendor, so only then are pairs built
        if len(vendors) == 1:
            for product in products:
                pairs.add((vendors[0], product))
    return pairs


def rebuild_catalog(db: Session, batch_size: int = 2000) -> dict:
    """Recount every vendor/product pair in the CVE data. Returns a summary."""
    counts: dict = {}
    query = db.query(
        Vulnerability.affected_products, Vulnerability.vendors, Vulnerability.products
    ).yield_per(batch_size)
    scanned = 0
    for affected, vendors, products in query:
        scanned += 1
        holder = SimpleNamespace(
            affected_products=affected, vendors=vendors, products=products
        )
        for pair in vulnerability_pairs(holder):
            counts[pair] = counts.get(pair, 0) + 1

    db.query(ProductCatalog).delete(synchronize_session=False)
    rows = [
        ProductCatalog(vendor=v[:255], product=p[:255], cve_count=n)
        for (v, p), n in counts.items()
    ]
    # Chunked, so a big catalog does not become one huge statement
    for start in range(0, len(rows), 5000):
        db.bulk_save_objects(rows[start : start + 5000])
    db.commit()
    logger.info("Product catalog rebuilt: %s pairs from %s CVEs", len(rows), scanned)
    return {"products": len(rows), "vulnerabilities": scanned}


# --- matching: SQL ---------------------------------------------------------


def _escape(value: str) -> str:
    """Escape LIKE wildcards (underscores are common in product names)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _text(column):
    return func.lower(cast(column, Text))


def watch_clause(vendor: str, product: Optional[str]):
    """SQL condition: the CVE concerns this vendor (and product)."""
    vendor = slug(vendor)
    product = slug(product) if product else None
    affected = _text(Vulnerability.affected_products)
    vendors = _text(Vulnerability.vendors)
    products = _text(Vulnerability.products)

    v, p = _escape(vendor), _escape(product) if product else None
    # In the CPE pattern the single "_" after "cpe:2.3:" is meant as a wildcard
    # for the part letter (a, o, h)
    if product:
        by_cpe = affected.like(f"%cpe:2.3:_:{v}:{p}:%", escape="\\")
        by_name = and_(
            vendors.like(f'%"{_escape(vendor.replace("_", " "))}"%', escape="\\"),
            products.like(f'%"{_escape(product.replace("_", " "))}"%', escape="\\"),
        )
    else:
        by_cpe = affected.like(f"%cpe:2.3:_:{v}:%", escape="\\")
        by_name = vendors.like(f'%"{_escape(vendor.replace("_", " "))}"%', escape="\\")
    return or_(by_cpe, by_name)


def watches_clause(watches: Iterable[WatchedProduct]):
    clauses = [watch_clause(w.vendor, w.product) for w in watches]
    return or_(*clauses) if clauses else None


def matching_query(
    db: Session,
    watches: Sequence[WatchedProduct],
    since: Optional[datetime] = None,
    min_severity: Optional[str] = None,
    kev_only: bool = False,
):
    """CVEs concerning any followed product, newest first. None-safe for no watches."""
    clause = watches_clause(watches)
    query = db.query(Vulnerability)
    if clause is None:
        return query.filter(False)
    query = query.filter(clause)
    if since is not None:
        query = query.filter(Vulnerability.published_at >= since)
    allowed = severities_from(min_severity)
    if allowed:
        query = query.filter(Vulnerability.severity.in_(allowed))
    if kev_only:
        query = query.filter(Vulnerability.exploited_in_the_wild.is_(True))
    return query


# --- matching: Python ------------------------------------------------------


def matching_watches(vuln: Vulnerability, watches: Iterable[WatchedProduct]) -> List[WatchedProduct]:
    """Which of the followed products does this CVE concern? (Python twin of the SQL.)"""
    cpe_pairs = set()
    for cpe in vuln.affected_products or []:
        pair = cpe_pair(cpe) if isinstance(cpe, str) else None
        if pair:
            cpe_pairs.add(pair)
    name_vendors = {slug(v) for v in (vuln.vendors or [])}
    name_products = {slug(p) for p in (vuln.products or [])}

    result = []
    for w in watches:
        if w.product:
            hit = (w.vendor, w.product) in cpe_pairs or (
                w.vendor in name_vendors and w.product in name_products
            )
        else:
            hit = any(v == w.vendor for v, _ in cpe_pairs) or w.vendor in name_vendors
        if hit:
            result.append(w)
    return result


# --- summaries -------------------------------------------------------------


def utc_since(days: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def window_counts(db: Session, watches: Sequence[WatchedProduct], days: float) -> dict:
    """New CVEs for the followed products in the last ``days`` days."""
    since = utc_since(days)
    base = matching_query(db, watches, since=since)
    total = base.count()
    return {
        "new": total,
        "critical": base.filter(Vulnerability.severity == "CRITICAL").count(),
        "high": base.filter(Vulnerability.severity == "HIGH").count(),
        "exploited": base.filter(Vulnerability.exploited_in_the_wild.is_(True)).count(),
    }
