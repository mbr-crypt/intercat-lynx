"""BSI CERT-Bund warnings: CSAF parsing, safe download, taking over, API."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.models import BsiAdvisory, BsiAdvisoryCve
from backend.services import bsi_service, settings_service, task_activity
from tests.test_setup_api import _admin_token
from tests.test_watchlist import h

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
BASE = "https://wid.cert-bund.de/.well-known/csaf/white/2026/"


def csaf(number, cves=("CVE-2026-1111",), severity="hoch", updated="2026-10-24T08:00:00.000+00:00"):
    """A CSAF 2.0 document in the shape the WID uses (vendor > product > version)."""
    return {
        "document": {
            "title": f"Beispiel Produkt: Mehrere Schwachstellen {number}",
            "aggregate_severity": {"text": severity},
            "tracking": {
                "id": f"WID-SEC-W-2026-{number}",
                "initial_release_date": "2026-10-20T10:00:00.000+00:00",
                "current_release_date": updated,
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Beispiel AG",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "Server",
                            "branches": [{"category": "product_version", "name": "1.0"}],
                        },
                        {"category": "product_name", "name": "Beispiel AG Client"},
                    ],
                }
            ]
        },
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def feed(entries):
    return {
        "feed": {
            "entry": [
                {"id": e[0], "updated": e[1], "content": {"type": "application/json", "src": BASE + e[0] + ".json"}}
                for e in entries
            ]
        }
    }


class FakeBsi:
    """Replaces the download: serves a feed and documents, counts calls."""

    def __init__(self, entries, docs, etag='"abc"'):
        self.feed = feed(entries)
        self.docs = docs
        self.etag = etag
        self.calls = []

    def __call__(self, url, headers, max_bytes):
        self.calls.append((url, dict(headers)))
        if url == bsi_service.FEED_URL:
            if headers.get("If-None-Match") == self.etag:
                return 304, b"", {}
            return 200, json.dumps(self.feed).encode(), {"ETag": self.etag}
        name = url.rsplit("/", 1)[-1][:-5]
        if name in self.docs:
            return 200, json.dumps(self.docs[name]).encode(), {}
        return 404, b"", {}


def run(db, fake, **kw):
    return bsi_service.run(db, fetcher=fake, now=NOW, pause=0, **kw)


# --- parsing -----------------------------------------------------------------


def test_parse_advisory_takes_the_index_data():
    data = bsi_service.parse_advisory(csaf("0042", ("CVE-2026-1", "cve-2026-0002", "kaputt")), "u")
    assert data["advisory_id"] == "WID-SEC-W-2026-0042"
    assert data["severity"] == "hoch"
    # a malformed number is dropped, lower case is repaired, duplicates removed
    assert data["cves"] == ["CVE-2026-0002"]
    assert data["products"] == ["Beispiel AG Server", "Beispiel AG Client"]
    assert data["updated_at"] == datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc)
    assert data["url"].endswith("name=WID-SEC-2026-0042")  # the portal writes the number without "-W-"


def test_parse_advisory_accepts_english_severity_and_rejects_nonsense():
    assert bsi_service.parse_advisory(csaf("1", severity="Critical"), "u")["severity"] == "kritisch"
    assert bsi_service.parse_advisory(csaf("1", severity="seltsam"), "u")["severity"] is None
    for bad in ({}, {"document": []}, {"document": {"title": "x", "tracking": {}}}):
        with pytest.raises(bsi_service.BsiError):
            bsi_service.parse_advisory(bad, "u")


def test_feed_entries_with_foreign_addresses_are_dropped():
    raw = {
        "feed": {
            "entry": [
                {"updated": "2026-10-24T00:00:00Z", "content": {"src": BASE + "a.json"}},
                {"updated": "2026-10-24T00:00:00Z", "content": {"src": "https://evil.example/a.json"}},
                {"updated": "2026-10-24T00:00:00Z", "content": {"src": "http://wid.cert-bund.de/a.json"}},
                {"updated": "2026-10-24T00:00:00Z", "content": {"src": "https://wid.cert-bund.de.evil.example/a.json"}},
                {"updated": "kaputt", "content": {"src": BASE + "b.json"}},
                "kein objekt",
            ]
        }
    }
    assert [e["url"] for e in bsi_service.parse_feed(raw)] == [BASE + "a.json"]


@pytest.mark.parametrize(
    "url",
    [
        "http://wid.cert-bund.de/x",
        "https://example.org/x",
        "https://wid.cert-bund.de@evil.example/x",
        "https://wid.cert-bund.de:8443/x",
        "file:///etc/passwd",
    ],
)
def test_only_the_bsi_host_over_https_is_allowed(url):
    with pytest.raises(bsi_service.BsiError):
        bsi_service._check_url(url)


def test_the_green_feeds_are_never_used():
    assert "/white/" in bsi_service.FEED_URL and "green" not in bsi_service.FEED_URL


# --- taking over -------------------------------------------------------------


def test_first_run_takes_over_new_warnings(db_session):
    fake = FakeBsi(
        [("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z"), ("wid-sec-w-2026-0002", "2026-10-23T08:00:00Z")],
        {"wid-sec-w-2026-0001": csaf("0001", ("CVE-2026-1111", "CVE-2026-2222")), "wid-sec-w-2026-0002": csaf("0002")},
    )
    result = run(db_session, fake)
    assert result["new"] == 2 and result["failed"] == 0
    row = db_session.query(BsiAdvisory).filter_by(advisory_id="WID-SEC-W-2026-0001").one()
    assert row.cve_count == 2 and sorted(c.cve_id for c in row.cves) == ["CVE-2026-1111", "CVE-2026-2222"]
    assert row.feed_updated_at is not None and row.csaf_url.startswith(BASE)
    assert settings_service.get(db_session, bsi_service.KEY_LAST_SYNC)


def test_old_entries_are_not_taken_over_on_the_first_run(db_session):
    old = (NOW - timedelta(days=bsi_service.INITIAL_DAYS + 5)).isoformat()
    fake = FakeBsi([("wid-sec-w-2026-0001", old)], {"wid-sec-w-2026-0001": csaf("0001")})
    assert run(db_session, fake)["new"] == 0


def test_second_run_with_unchanged_feed_costs_one_request(db_session):
    fake = FakeBsi([("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z")], {"wid-sec-w-2026-0001": csaf("0001")})
    run(db_session, fake)
    fake.calls.clear()
    result = run(db_session, fake)
    assert result.get("unchanged") == 1
    assert len(fake.calls) == 1 and fake.calls[0][1]["If-None-Match"] == '"abc"'


def test_changed_warning_is_updated_and_cves_replaced(db_session):
    fake = FakeBsi(
        [("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z")],
        {"wid-sec-w-2026-0001": csaf("0001", ("CVE-2026-1111", "CVE-2026-2222"))},
    )
    run(db_session, fake)
    fake2 = FakeBsi(
        [("wid-sec-w-2026-0001", "2026-10-25T09:00:00Z")],
        {"wid-sec-w-2026-0001": csaf("0001", ("CVE-2026-2222", "CVE-2026-3333"), severity="kritisch")},
        etag='"neu"',
    )
    result = run(db_session, fake2)
    assert result["updated"] == 1 and result["new"] == 0
    db_session.expire_all()
    row = db_session.query(BsiAdvisory).one()
    assert row.severity == "kritisch"
    assert sorted(c.cve_id for c in row.cves) == ["CVE-2026-2222", "CVE-2026-3333"]
    assert db_session.query(BsiAdvisoryCve).count() == 2


def test_known_documents_are_not_downloaded_again(db_session):
    fake = FakeBsi([("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z")], {"wid-sec-w-2026-0001": csaf("0001")})
    run(db_session, fake)
    settings_service.delete(db_session, bsi_service.KEY_ETAG)  # force a feed download
    fake.calls.clear()
    assert run(db_session, fake)["new"] == 0
    assert [c[0] for c in fake.calls] == [bsi_service.FEED_URL]


def test_one_broken_document_does_not_stop_the_run(db_session):
    fake = FakeBsi(
        [("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z"), ("wid-sec-w-2026-0002", "2026-10-23T08:00:00Z")],
        {"wid-sec-w-2026-0002": csaf("0002")},  # 0001 is missing (404)
    )
    result = run(db_session, fake)
    assert result["new"] == 1 and result["failed"] == 1
    # the starting point is not moved, the next run tries again
    assert settings_service.get(db_session, bsi_service.KEY_LAST_SYNC) is None


def test_many_documents_are_split_over_several_runs(db_session, monkeypatch):
    monkeypatch.setattr(bsi_service, "MAX_DOCS_PER_RUN", 2)
    names = [f"wid-sec-w-2026-{i:04d}" for i in range(1, 6)]
    fake = FakeBsi(
        [(n, f"2026-10-24T0{i}:00:00Z") for i, n in enumerate(names)],
        {n: csaf(n[-4:]) for n in names},
    )
    first = run(db_session, fake)
    assert first["new"] == 2 and first["remaining"] == 1
    assert settings_service.get(db_session, bsi_service.KEY_LAST_SYNC) is None
    run(db_session, fake)
    third = run(db_session, fake)
    assert db_session.query(BsiAdvisory).count() == 5
    assert third["remaining"] == 0 and settings_service.get(db_session, bsi_service.KEY_LAST_SYNC)


def test_feed_error_raises(db_session):
    def broken(url, headers, max_bytes):
        return 503, b"", {}

    with pytest.raises(bsi_service.BsiError):
        bsi_service.run(db_session, fetcher=broken, now=NOW, pause=0)


def test_feed_that_is_not_json_raises(db_session):
    with pytest.raises(bsi_service.BsiError):
        bsi_service.run(db_session, fetcher=lambda u, h_, m: (200, b"<html>", {}), now=NOW, pause=0)


def test_switch_off_means_no_request(db_session, monkeypatch):
    fake = FakeBsi([], {})
    settings_service.set_value(db_session, bsi_service.KEY_ENABLED, "false")
    assert run(db_session, fake)["disabled"] is True and fake.calls == []
    settings_service.delete(db_session, bsi_service.KEY_ENABLED)
    monkeypatch.setenv("BSI_ENABLED", "false")
    assert bsi_service.is_enabled(db_session) is False
    monkeypatch.setenv("BSI_ENABLED", "true")
    assert bsi_service.is_enabled(db_session) is True


def test_task_is_registered_and_scheduled():
    from backend.celery_app import celery_app

    assert celery_app.conf.beat_schedule["fetch-bsi-csaf"]["task"] == "tasks.fetch_bsi_csaf"
    assert "fetch-bsi-csaf" in task_activity.SCHEDULED
    assert "tasks.fetch_bsi_csaf" in celery_app.tasks


def test_task_reports_only_the_error_type(monkeypatch, session_factory):
    from backend.tasks import data_tasks

    def boom(db):
        raise RuntimeError("https://geheim.example/?token=abc")

    monkeypatch.setattr(bsi_service, "run", boom)
    monkeypatch.setattr(data_tasks, "get_db", lambda: iter([session_factory()]))
    result = data_tasks.fetch_bsi_csaf_task.run()
    assert result == {"status": "error", "message": "RuntimeError"}


# --- API ---------------------------------------------------------------------


@pytest.fixture
def stored(db_session):
    fake = FakeBsi(
        [("wid-sec-w-2026-0001", "2026-10-24T08:00:00Z"), ("wid-sec-w-2026-0002", "2026-10-23T08:00:00Z")],
        {
            "wid-sec-w-2026-0001": csaf("0001", ("CVE-2026-1111",), severity="kritisch"),
            "wid-sec-w-2026-0002": csaf(
                "0002", ("CVE-2026-2222",), severity="niedrig", updated="2026-10-23T08:00:00.000+00:00"
            ),
        },
    )
    run(db_session, fake)


def test_list_is_newest_first_with_source(client, stored):
    r = client.get("/api/v1/bsi/advisories")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2 and "BSI" in body["source"]
    assert [i["advisory_id"] for i in body["items"]] == ["WID-SEC-W-2026-0001", "WID-SEC-W-2026-0002"]
    assert body["items"][0]["url"].startswith("https://wid.cert-bund.de/")


def test_list_filters(client, stored):
    assert client.get("/api/v1/bsi/advisories?severity=kritisch").json()["total"] == 1
    assert client.get("/api/v1/bsi/advisories?q=0002").json()["total"] == 1
    assert client.get("/api/v1/bsi/advisories?q=CVE-2026-2222").json()["total"] == 1
    assert client.get("/api/v1/bsi/advisories?q=%25").json()["total"] == 0  # % is not a wildcard
    assert client.get("/api/v1/bsi/advisories?severity=egal").status_code == 422


def test_lookup_by_cve(client, stored):
    r = client.get("/api/v1/bsi/cve/cve-2026-1111")
    assert r.status_code == 200 and [a["advisory_id"] for a in r.json()] == ["WID-SEC-W-2026-0001"]
    assert client.get("/api/v1/bsi/cve/CVE-2026-9999").json() == []
    assert client.get("/api/v1/bsi/cve/kaputt").status_code == 422


def test_admin_functions_need_an_administrator(client, db_session):
    assert client.get("/api/v1/bsi/status").status_code in (401, 403)
    assert client.put("/api/v1/bsi/settings", json={"enabled": False}).status_code in (401, 403)
    assert client.post("/api/v1/bsi/fetch").status_code in (401, 403)
    from backend.models import UserRole

    viewer = _admin_token(client, db_session, "viewer1", UserRole.VIEWER)
    assert client.get("/api/v1/bsi/status", headers=h(viewer)).status_code == 403
    assert client.put("/api/v1/bsi/settings", json={"enabled": False}, headers=h(viewer)).status_code == 403
    assert client.post("/api/v1/bsi/fetch", headers=h(viewer)).status_code == 403


def test_admin_can_switch_and_sees_status(client, db_session, stored):
    admin = h(_admin_token(client, db_session))
    status = client.get("/api/v1/bsi/status", headers=admin).json()
    assert status["enabled"] is True and status["advisories"] == 2 and status["last_sync"]
    r = client.put("/api/v1/bsi/settings", json={"enabled": False}, headers=admin)
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert client.post("/api/v1/bsi/fetch", headers=admin).status_code == 409


def test_manual_fetch_queues_the_task(client, db_session, monkeypatch):
    from backend.tasks import data_tasks

    queued = []
    monkeypatch.setattr(data_tasks.fetch_bsi_csaf_task, "delay", lambda: queued.append(1))
    admin = h(_admin_token(client, db_session))
    assert client.post("/api/v1/bsi/fetch", headers=admin).json() == {"status": "queued"}
    assert queued == [1]
