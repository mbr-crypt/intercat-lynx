"""
CVE counts over time ("how many new CVEs per day, week or month").

One daily GROUP BY runs in the database, the rest (weeks, months, filling
days without CVEs with zero) is done here. That keeps the SQL identical for
PostgreSQL and SQLite, and the amount of data small: at most 366 days times
five severities, or fewer.

"Date" is the day a CVE was *published* (``published_at``), in UTC.
"""

from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Query, Session

from ..models import Vulnerability

PERIODS = ("day", "week", "month")
SEVERITY_KEYS = ("critical", "high", "medium", "low", "unknown")

# How far back each granularity may look. A day chart over ten years would be
# 3650 bars and no one can read that; the limits keep every chart legible.
MAX_DAYS = {"day": 366, "week": 3 * 366, "month": 10 * 366}
DEFAULT_DAYS = {"day": 90, "week": 366, "month": 5 * 366}


def today_utc() -> date:
    return datetime.now(timezone.utc).date()


def bucket_start(day: date, period: str) -> date:
    """First day of the day/week (Monday)/month that contains ``day``."""
    if period == "week":
        return day - timedelta(days=day.weekday())
    if period == "month":
        return day.replace(day=1)
    return day


def next_bucket(start: date, period: str) -> date:
    if period == "week":
        return start + timedelta(days=7)
    if period == "month":
        return (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start + timedelta(days=1)


def _as_date(value) -> Optional[date]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _empty_bucket(start: date) -> Dict:
    bucket = {"date": start.isoformat(), "total": 0, "exploited": 0, "partial": False}
    for key in SEVERITY_KEYS:
        bucket[key] = 0
    return bucket


def trend(db: Session, query: Query, period: str, days: int) -> Dict:
    """
    Count the CVEs of ``query`` (a query on Vulnerability, already filtered to
    the products/whatever should count) per bucket.

    Returns ``{"period", "from", "to", "buckets", "total", "previous_total"}``.
    The range starts at the beginning of the bucket that contains
    ``today - days``, so the first bucket is always complete. The last bucket
    is flagged ``partial``: today's day/week/month is not over yet.
    """
    if period not in PERIODS:
        raise ValueError("period must be day, week or month")

    end = today_utc()
    start = bucket_start(end - timedelta(days=days), period)

    buckets: Dict[date, Dict] = {}
    cursor = start
    while cursor <= end:
        buckets[cursor] = _empty_bucket(cursor)
        cursor = next_bucket(cursor, period)
    # The bucket that contains today is still running, so it is always incomplete
    buckets[bucket_start(end, period)]["partial"] = True

    since = datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc)
    day_col = func.date(Vulnerability.published_at)
    rows = (
        query.order_by(None)
        .filter(Vulnerability.published_at >= since)
        .with_entities(
            day_col,
            Vulnerability.severity,
            func.count(Vulnerability.id),
            func.sum(case((Vulnerability.exploited_in_the_wild.is_(True), 1), else_=0)),
        )
        .group_by(day_col, Vulnerability.severity)
        .all()
    )

    for raw_day, severity, count, exploited in rows:
        day = _as_date(raw_day)
        if day is None or day > end:
            continue
        bucket = buckets.get(bucket_start(day, period))
        if bucket is None:
            continue
        key = (severity or "unknown").lower()
        if key not in SEVERITY_KEYS:
            key = "unknown"
        bucket[key] += count
        bucket["total"] += count
        bucket["exploited"] += int(exploited or 0)

    ordered: List[Dict] = [buckets[k] for k in sorted(buckets)]
    total = sum(b["total"] for b in ordered)

    span = (end - start).days + 1
    prev_since = datetime.combine(start - timedelta(days=span), datetime.min.time(), tzinfo=timezone.utc)
    previous_total = (
        query.order_by(None)
        .filter(Vulnerability.published_at >= prev_since, Vulnerability.published_at < since)
        .count()
    )

    return {
        "period": period,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "buckets": ordered,
        "total": total,
        "previous_total": previous_total,
    }
