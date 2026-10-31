"""Metric labels must not grow with attacker-chosen URLs."""

from backend.middleware.metrics import http_requests_total


def _endpoints():
    return {
        sample.labels["endpoint"]
        for metric in http_requests_total.collect()
        for sample in metric.samples
    }


def test_unknown_urls_share_one_label(client):
    for i in range(25):
        client.get(f"/no-such-page-{i}-xyz")
    seen = _endpoints()
    assert not any("no-such-page" in e for e in seen)
    assert "unmatched" in seen


def test_ids_in_a_path_collapse_to_the_route_template(client):
    for cve in ("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"):
        client.get(f"/api/v1/vulnerabilities/{cve}")
    seen = _endpoints()
    assert not any("CVE-2099" in e for e in seen)
    assert any("{" in e for e in seen)


def test_label_contains_the_router_prefix(client):
    client.get("/api/v1/vulnerabilities")
    client.get("/api/v1/vulnerabilities/CVE-2099-0009")
    client.get("/api/v1/stats")
    seen = _endpoints()
    assert "/api/v1/vulnerabilities" in seen
    assert "/api/v1/vulnerabilities/{cve_id}" in seen
    assert "/api/v1/stats" in seen
    assert "" not in seen
