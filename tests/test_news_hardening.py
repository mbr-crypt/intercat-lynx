"""News ingestion: hostile feed content must stay cheap and harmless."""

import time

from backend.services import news_service
from backend.services.news_service import NewsService, safe_http_url

RSS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Bad</title><link>javascript:alert(document.domain)</link></item>
<item><title>Good</title><link>https://example.org/a</link></item>
<item><title>Data</title><link>data:text/html;base64,PHNjcmlwdD4=</link></item>
</channel></rss>"""

ATOM = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Bad</title><link href="javascript:alert(1)"/></entry>
<entry><title>Good</title><link href="https://example.org/b"/></entry>
</feed>"""


def _service():
    return NewsService.__new__(NewsService)


def test_only_http_links_are_accepted():
    assert safe_http_url("https://example.org/x") == "https://example.org/x"
    assert safe_http_url("  http://example.org  ") == "http://example.org"
    for bad in ("javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "//example.org", "/rel", "", None):
        assert safe_http_url(bad) is None


def test_rss_items_with_script_links_are_dropped():
    urls = [a["url"] for a in _service().parse_rss_feed(RSS)]
    assert urls == ["https://example.org/a"]


def test_atom_entries_with_script_links_are_dropped():
    urls = [a["url"] for a in _service().parse_rss_feed(ATOM)]
    assert urls == ["https://example.org/b"]


def test_clean_html_stays_fast_on_hostile_input():
    hostile = "<" * 200000 + "a"
    started = time.monotonic()
    _service()._clean_html(hostile)
    assert time.monotonic() - started < 1.0
    started = time.monotonic()
    _service()._clean_html("<" + "a" * 5_000_000)
    assert time.monotonic() - started < 1.0


def test_clean_html_still_strips_tags_and_entities():
    assert _service()._clean_html("<p>Hello <b>world</b> &amp; more</p>") == "Hello world & more"


class _Resp:
    def __init__(self, chunks):
        self._chunks = chunks
        self.encoding = "utf-8"

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=0):
        yield from self._chunks

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_oversized_feed_is_cut_off(monkeypatch):
    svc = _service()
    big = [b"x" * 65536] * 200  # 12.5 MB
    svc.session = type("S", (), {"get": lambda self, url, **k: _Resp(big)})()
    assert svc.fetch_feed("https://example.org/feed") is None


def test_normal_feed_is_returned(monkeypatch):
    svc = _service()
    svc.session = type("S", (), {"get": lambda self, url, **k: _Resp([b"<rss>", b"</rss>"])})()
    assert svc.fetch_feed("https://example.org/feed") == "<rss></rss>"
