"""
Numbers for monitoring (Zabbix): counts of CVEs for the followed products.

Zabbix polls these over HTTP and decides itself what is an alarm (triggers), so
this module only reports facts: how many CVEs in the last 24 hours / 7 days,
how many of them critical, high or actively exploited, and the worst CVSS score.
"""

from typing import Dict, List, Sequence, Tuple

from sqlalchemy.orm import Session

from ..models import Vulnerability, WatchedProduct
from . import watchlist_service as wl


def watch_key(w: WatchedProduct) -> str:
    """Stable id of a followed product inside the JSON (vendor or vendor:product)."""
    return f"{w.vendor}:{w.product}" if w.product else w.vendor


def _aggregate(rows: Dict[int, tuple]) -> dict:
    day_ago = wl.utc_since(1)
    out = {
        "new_24h": 0, "critical_24h": 0, "high_24h": 0, "exploited_24h": 0,
        "new_7d": 0, "critical_7d": 0, "high_7d": 0, "exploited_7d": 0,
        "max_cvss_7d": 0.0,
    }
    for published, severity, score, exploited in rows.values():
        if published is not None and published.tzinfo is None:
            published = published.replace(tzinfo=day_ago.tzinfo)
        recent = published is not None and published >= day_ago
        out["new_7d"] += 1
        out["critical_7d"] += severity == "CRITICAL"
        out["high_7d"] += severity == "HIGH"
        out["exploited_7d"] += bool(exploited)
        if recent:
            out["new_24h"] += 1
            out["critical_24h"] += severity == "CRITICAL"
            out["high_24h"] += severity == "HIGH"
            out["exploited_24h"] += bool(exploited)
        if score is not None:
            out["max_cvss_7d"] = max(out["max_cvss_7d"], float(score))
    return out


def compute(db: Session, watches: Sequence[WatchedProduct]) -> Tuple[dict, List[dict]]:
    """(summary over all followed products, one entry per followed product)."""
    since = wl.utc_since(7)
    per_watch: Dict[int, Dict[int, tuple]] = {}
    everything: Dict[int, tuple] = {}
    for w in watches:
        found = (
            db.query(
                Vulnerability.id,
                Vulnerability.published_at,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                Vulnerability.exploited_in_the_wild,
            )
            .filter(wl.watch_clause(w.vendor, w.product), Vulnerability.published_at >= since)
            .all()
        )
        rows = {r[0]: r[1:] for r in found}
        per_watch[w.id] = rows
        everything.update(rows)

    items = [
        {
            "key": watch_key(w),
            "vendor": w.vendor,
            "product": w.product or "",
            "label": wl.watch_label(w.vendor, w.product),
            **_aggregate(per_watch[w.id]),
        }
        for w in watches
    ]
    summary = {"watch_count": len(watches), **_aggregate(everything)}
    return summary, items
