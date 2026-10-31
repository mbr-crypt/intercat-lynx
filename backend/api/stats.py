"""
Statistics and dashboard endpoints.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, desc, func, text
from sqlalchemy.orm import Session

from ..database import REDIS_URL, get_db
from ..models import IngestionRun, Vulnerability
from ..schemas import StatsResponse
from ..services import trend_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis connection for caching
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
STATS_CACHE_KEY = "dashboard:stats"
STATS_CACHE_TTL = 300  # 5 minutes


@router.get("/stats", response_model=StatsResponse)
async def get_statistics(db: Session = Depends(get_db)):
    """
    Get overall statistics for the dashboard (cached for 5 minutes).

    Returns:
    - Total vulnerabilities
    - Exploited vulnerabilities
    - Breakdown by severity
    - Recent updates count
    - Last update timestamp
    """
    # 1) Redis cache (best effort - a missing Redis must never break the endpoint)
    try:
        cached = redis_client.get(STATS_CACHE_KEY)
        if cached:
            return StatsResponse(**json.loads(cached))
    except Exception as e:
        logger.warning("Stats cache read failed: %s", e)

    # 2) Pre-calculated table (fast on large databases), 3) live counts
    counts = _read_stats_cache_table(db)
    if counts is None:
        counts = _count_live(db)

    last_run = (
        db.query(IngestionRun)
        .filter(IngestionRun.status == "success")
        .order_by(desc(IngestionRun.completed_at))
        .first()
    )

    result = StatsResponse(
        total_vulnerabilities=counts["total"],
        exploited_vulnerabilities=counts["exploited"],
        critical_vulnerabilities=counts["CRITICAL"],
        high_vulnerabilities=counts["HIGH"],
        by_severity={
            level: counts[level]
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        },
        recent_updates=counts["recent"],
        last_update=last_run.completed_at if last_run else None,
    )

    try:
        redis_client.setex(
            STATS_CACHE_KEY,
            STATS_CACHE_TTL,
            json.dumps(result.model_dump(), default=str),
        )
    except Exception as e:
        logger.warning("Stats cache write failed: %s", e)

    return result


def _read_stats_cache_table(db: Session) -> Optional[dict]:
    """
    Read the pre-calculated counters from ``vulnerability_stats_cache``.

    Returns None when the table does not exist (e.g. SQLite, fresh install
    before the SQL migration ran) or holds no usable data, so the caller can
    fall back to live counting instead of reporting zeros.
    """
    try:
        row = (
            db.execute(
                text(
                    "SELECT total_vulnerabilities, exploited_vulnerabilities, "
                    "critical_vulnerabilities, high_vulnerabilities, "
                    "medium_vulnerabilities, low_vulnerabilities, "
                    "unknown_vulnerabilities, recent_updates "
                    "FROM vulnerability_stats_cache WHERE id = 1"
                )
            )
            .mappings()
            .fetchone()
        )
    except Exception as e:
        # On PostgreSQL a failed statement aborts the transaction -> reset it.
        db.rollback()
        logger.info("Stats cache table not available, counting live: %s", e)
        return None

    if row is None or not row["total_vulnerabilities"]:
        return None

    return {
        "total": row["total_vulnerabilities"],
        "exploited": row["exploited_vulnerabilities"],
        "CRITICAL": row["critical_vulnerabilities"],
        "HIGH": row["high_vulnerabilities"],
        "MEDIUM": row["medium_vulnerabilities"],
        "LOW": row["low_vulnerabilities"],
        "UNKNOWN": row["unknown_vulnerabilities"],
        "recent": row["recent_updates"],
    }


def _count_live(db: Session) -> dict:
    """Count directly from the vulnerabilities table (always correct, slower)."""
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    total, exploited, recent = db.query(
        func.count(Vulnerability.id),
        func.coalesce(
            func.sum(case((Vulnerability.exploited_in_the_wild.is_(True), 1), else_=0)),
            0,
        ),
        func.coalesce(
            func.sum(case((Vulnerability.published_at >= week_ago, 1), else_=0)), 0
        ),
    ).one()

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for severity, count in (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    ):
        key = (severity or "UNKNOWN").upper()
        by_severity[key if key in by_severity else "UNKNOWN"] += count

    return {
        "total": total,
        "exploited": int(exploited),
        "recent": int(recent),
        **by_severity,
    }


TOP_VENDORS_CACHE_KEY = "dashboard:top-vendors"
TOP_VENDORS_MAX = 100


def _count_vendors(db: Session) -> list:
    """Vendor counts over the whole table, highest first (at most TOP_VENDORS_MAX)."""
    vendor_counts: dict = {}
    # yield_per streams the rows in batches instead of loading the table at once
    rows = (
        db.query(Vulnerability.vendors)
        .filter(Vulnerability.vendors.isnot(None))
        .yield_per(1000)
    )
    for (vendors,) in rows:
        for vendor in vendors or []:
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    top = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:TOP_VENDORS_MAX]
    return [{"name": vendor, "count": count} for vendor, count in top]


# A plain ``def`` (not ``async def``): FastAPI runs it in a worker thread. The
# counting loop below is synchronous work that grows with the table; on the
# event loop it would stall every other request of the uvicorn worker.
@router.get("/stats/top-vendors")
def get_top_vendors(
    limit: int = Query(20, ge=1, le=TOP_VENDORS_MAX), db: Session = Depends(get_db)
):
    """
    Get top vendors by vulnerability count (cached for 5 minutes).

    **Query Parameters:**
    - `limit`: Number of vendors to return (default: 20, 1-100)
    """
    vendors = None
    try:
        cached = redis_client.get(TOP_VENDORS_CACHE_KEY)
        if cached:
            vendors = json.loads(cached)
    except Exception as e:
        logger.warning("Top-vendors cache read failed: %s", e)

    if vendors is None:
        vendors = _count_vendors(db)
        try:
            redis_client.setex(TOP_VENDORS_CACHE_KEY, STATS_CACHE_TTL, json.dumps(vendors))
        except Exception as e:
            logger.warning("Top-vendors cache write failed: %s", e)

    return {"vendors": vendors[:limit]}


@router.get("/stats/severity-distribution")
async def get_severity_distribution(db: Session = Depends(get_db)):
    """
    Get vulnerability distribution by severity.

    Returns counts and percentages for each severity level.
    """
    total = db.query(func.count(Vulnerability.id)).scalar() or 1

    severity_counts = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )

    distribution = []
    for severity, count in severity_counts:
        distribution.append(
            {
                "severity": severity or "UNKNOWN",
                "count": count,
                "percentage": round((count / total) * 100, 2),
            }
        )

    # Sort by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    distribution.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return {"distribution": distribution, "total": total}


@router.get("/stats/timeline")
async def get_vulnerability_timeline(days: int = 30, db: Session = Depends(get_db)):
    """
    Get vulnerability publication timeline.

    Returns daily counts of published vulnerabilities for the last N days.

    **Query Parameters:**
    - `days`: Number of days to include (default: 30)
    """
    from sqlalchemy import Date, cast, func

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    timeline = (
        db.query(
            cast(Vulnerability.published_at, Date).label("date"),
            func.count(Vulnerability.id).label("count"),
        )
        .filter(Vulnerability.published_at >= cutoff)
        .group_by(cast(Vulnerability.published_at, Date))
        .order_by(cast(Vulnerability.published_at, Date))
        .all()
    )

    return {
        "timeline": [{"date": str(date), "count": count} for date, count in timeline]
    }


@router.get("/stats/ingestion-history")
async def get_ingestion_history(limit: int = 10, db: Session = Depends(get_db)):
    """
    Get recent ingestion run history.

    **Query Parameters:**
    - `limit`: Number of runs to return (default: 10)
    """
    runs = (
        db.query(IngestionRun)
        .order_by(desc(IngestionRun.started_at))
        .limit(limit)
        .all()
    )

    return {
        "runs": [
            {
                "id": run.id,
                "source": run.source,
                "status": run.status,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": (
                    run.completed_at.isoformat() if run.completed_at else None
                ),
                "duration_seconds": run.duration_seconds,
                "records_fetched": run.records_fetched,
                "records_inserted": run.records_inserted,
                "records_updated": run.records_updated,
                "records_failed": run.records_failed,
            }
            for run in runs
        ]
    }


@router.get("/stats/trend")
async def get_trend(
    period: str = Query("day", pattern="^(day|week|month)$"),
    days: Optional[int] = Query(None, ge=1, le=3660),
    db: Session = Depends(get_db),
):
    """
    New CVEs over time, per day, week (Monday) or month, split by severity.

    `days` is how far back to look; the default and the maximum depend on the
    period (day: 90 / 366, week: 366 / 1098, month: 1830 / 3660).
    """
    days = days or trend_service.DEFAULT_DAYS[period]
    if days > trend_service.MAX_DAYS[period]:
        raise HTTPException(
            status_code=400,
            detail=f"For period={period} at most {trend_service.MAX_DAYS[period]} days are allowed",
        )
    return trend_service.trend(db, db.query(Vulnerability), period, days)
