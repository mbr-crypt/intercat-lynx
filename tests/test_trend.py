"""CVEs over time: bucketing, severity split, own products, limits."""

from datetime import date, datetime, timedelta, timezone

import pytest

from backend.models import WatchedProduct
from backend.services import trend_service as ts
from tests.test_watchlist import add_cve, h, make_user, token_of


def test_bucket_helpers():
    assert ts.bucket_start(date(2026, 10, 23), "week") == date(2026, 10, 19)  # Monday
    assert ts.bucket_start(date(2026, 10, 19), "week") == date(2026, 10, 19)
    assert ts.bucket_start(date(2026, 10, 23), "month") == date(2026, 10, 1)
    assert ts.next_bucket(date(2026, 12, 1), "month") == date(2027, 1, 1)
    assert ts.next_bucket(date(2026, 2, 1), "month") == date(2026, 3, 1)
    assert ts.next_bucket(date(2026, 10, 19), "week") == date(2026, 10, 26)


def test_days_without_cves_are_zero_filled(client, db_session):
    add_cve(db_session, "CVE-2026-1001", 0, "CRITICAL", exploited=True)
    add_cve(db_session, "CVE-2026-1002", 0, "HIGH")
    add_cve(db_session, "CVE-2026-1003", 2, "LOW")
    r = client.get("/api/v1/stats/trend?period=day&days=6")
    assert r.status_code == 200
    body = r.json()
    dates = [b["date"] for b in body["buckets"]]
    assert dates == sorted(dates) and len(dates) == len(set(dates))
    assert len(dates) == 7  # 6 days back plus today
    assert dates[-1] == ts.today_utc().isoformat()
    last = body["buckets"][-1]
    assert (last["total"], last["critical"], last["high"], last["exploited"]) == (2, 1, 1, 1)
    assert sum(1 for b in body["buckets"] if b["total"] == 0) == 5
    assert body["total"] == 3


def test_severity_split_and_unknown(client, db_session):
    add_cve(db_session, "CVE-2026-1010", 0, "MEDIUM")
    add_cve(db_session, "CVE-2026-1011", 0, None)
    add_cve(db_session, "CVE-2026-1012", 0, "WEIRD")
    body = client.get("/api/v1/stats/trend?period=day&days=1").json()
    last = body["buckets"][-1]
    assert last["medium"] == 1
    assert last["unknown"] == 2
    assert last["total"] == 3


def test_week_and_month_add_up_to_the_same_total(client, db_session):
    for i, days_ago in enumerate([0, 3, 9, 20, 40, 75]):
        add_cve(db_session, f"CVE-2026-11{i:02d}", days_ago, "HIGH")
    totals = {}
    for period in ("day", "week", "month"):
        body = client.get(f"/api/v1/stats/trend?period={period}&days=120").json()
        totals[period] = body["total"]
        starts = [b["date"] for b in body["buckets"]]
        if period == "week":
            assert all(date.fromisoformat(s).weekday() == 0 for s in starts)
        if period == "month":
            assert all(s.endswith("-01") for s in starts)
    assert totals == {"day": 6, "week": 6, "month": 6}


def test_only_the_running_bucket_is_partial(client, db_session):
    for period in ("day", "week", "month"):
        body = client.get(f"/api/v1/stats/trend?period={period}&days=60").json()
        assert body["buckets"][-1]["partial"] is True
        assert all(b["partial"] is False for b in body["buckets"][:-1])


def test_previous_total_compares_the_period_before(client, db_session):
    add_cve(db_session, "CVE-2026-1201", 1, "HIGH")
    add_cve(db_session, "CVE-2026-1202", 12, "HIGH")
    add_cve(db_session, "CVE-2026-1203", 13, "HIGH")
    body = client.get("/api/v1/stats/trend?period=day&days=6").json()
    assert body["total"] == 1
    assert body["previous_total"] == 2


def test_default_days_and_limits(client, db_session):
    assert client.get("/api/v1/stats/trend").status_code == 200
    assert client.get("/api/v1/stats/trend?period=day&days=367").status_code == 400
    assert client.get("/api/v1/stats/trend?period=week&days=1098").status_code == 200
    assert client.get("/api/v1/stats/trend?period=hour").status_code == 422
    assert client.get("/api/v1/stats/trend?days=0").status_code == 422
    assert client.get("/api/v1/stats/trend?period=month&days=3661").status_code == 422


def test_my_trend_counts_only_followed_products(client, db_session):
    user = make_user(db_session, "trendy")
    add_cve(db_session, "CVE-2026-1301", 0, "CRITICAL",
            cpes=["cpe:2.3:o:fortinet:fortios:7.0:*:*:*:*:*:*:*"])
    add_cve(db_session, "CVE-2026-1302", 0, "HIGH",
            cpes=["cpe:2.3:a:microsoft:edge:1:*:*:*:*:*:*:*"])
    db_session.add(WatchedProduct(user_id=user.id, vendor="fortinet", product="fortios"))
    db_session.commit()
    token = token_of(client, "trendy")
    body = client.get("/api/v1/watchlist/trend?period=day&days=3", headers=h(token)).json()
    assert body["total"] == 1
    assert body["buckets"][-1]["critical"] == 1
    # the public numbers still see both
    assert client.get("/api/v1/stats/trend?period=day&days=3").json()["total"] == 2


def test_my_trend_without_follows_is_empty_and_needs_login(client, db_session):
    assert client.get("/api/v1/watchlist/trend").status_code in (401, 403)
    make_user(db_session, "nofollow")
    add_cve(db_session, "CVE-2026-1401", 0, "HIGH")
    token = token_of(client, "nofollow")
    body = client.get("/api/v1/watchlist/trend?period=week", headers=h(token)).json()
    assert body["total"] == 0 and body["previous_total"] == 0
    assert len(body["buckets"]) > 1
