"""Client address behind the proxy: a client-written X-Forwarded-For must not count."""

import pytest
from starlette.requests import Request

from backend.middleware.redis_rate_limit import redis_rate_limiter
from backend.middleware.rate_limit import rate_limiter
from backend.utils.client_ip import get_client_ip


def make_request(xff=None, peer="172.18.0.5", real_ip=None):
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    if real_ip is not None:
        headers.append((b"x-real-ip", real_ip.encode()))
    return Request({"type": "http", "headers": headers, "client": (peer, 5555), "method": "GET", "path": "/"})


def test_without_trusted_proxy_headers_are_ignored(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    assert get_client_ip(make_request("6.6.6.6", real_ip="7.7.7.7")) == "172.18.0.5"


def test_one_proxy_uses_the_last_entry(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")
    # nginx appended the real address to what the client wrote
    assert get_client_ip(make_request("6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert get_client_ip(make_request("203.0.113.9")) == "203.0.113.9"


def test_a_spoofed_first_entry_cannot_change_the_address(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")
    ips = {get_client_ip(make_request(f"10.0.0.{i}, 203.0.113.9")) for i in range(50)}
    assert ips == {"203.0.113.9"}


def test_two_proxies_use_the_second_to_last(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "2")
    assert get_client_ip(make_request("6.6.6.6, 203.0.113.9, 172.18.0.2")) == "203.0.113.9"


def test_missing_or_short_header_falls_back_to_the_connection(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "2")
    assert get_client_ip(make_request(None)) == "172.18.0.5"
    assert get_client_ip(make_request("203.0.113.9")) == "172.18.0.5"


@pytest.mark.parametrize("junk", ["not-an-ip", "a" * 5000, "999.1.1.1", "<script>"])
def test_garbage_is_not_used_as_a_key(monkeypatch, junk):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")
    assert get_client_ip(make_request(junk)) == "172.18.0.5"


def test_ipv6_is_normalised(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")
    assert get_client_ip(make_request("2001:DB8:0:0:0:0:0:1")) == "2001:db8::1"


def test_invalid_setting_means_no_trust(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "lots")
    assert get_client_ip(make_request("6.6.6.6, 1.1.1.1")) == "172.18.0.5"


def test_both_rate_limiters_use_the_same_rule(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")
    request = make_request("6.6.6.6, 203.0.113.9")
    assert redis_rate_limiter.get_client_ip(request) == "203.0.113.9"
    assert rate_limiter.get_client_ip(request) == "203.0.113.9"


def test_nginx_replaces_the_forwarded_header():
    """Guard against someone putting $proxy_add_x_forwarded_for back."""
    from pathlib import Path

    for name in ("nginx.conf", "nginx.dev.conf"):
        text = (Path(__file__).resolve().parent.parent / "nginx" / name).read_text()
        assert "$proxy_add_x_forwarded_for" not in text, name
        assert "proxy_set_header X-Forwarded-For $remote_addr;" in text, name
