"""Webhook delivery: pinned address, one total deadline, no body read."""

import socket
import threading
import time

import pytest

from backend.security import pinned_post


class _Server:
    """Tiny one-connection-at-a-time TCP server on 127.0.0.1."""

    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.seen = []
        self.stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            self.handler(conn, self.seen)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop = True
        self.sock.close()


def _read_request(conn):
    data = b""
    conn.settimeout(2)
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


@pytest.fixture()
def server():
    servers = []

    def make(handler):
        s = _Server(handler)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def test_returns_status_and_uses_host_name_in_header_but_connects_to_ip(server):
    def ok(conn, seen):
        seen.append(_read_request(conn))
        conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

    srv = server(ok)
    # the URL names a host that does not exist; only the pinned IP can work
    status = pinned_post.post(
        f"http://hook.invalid:{srv.port}/in?x=1", "127.0.0.1", b"{}", {"X-Test": "1"}, total_timeout=3
    )
    assert status == 204
    request = srv.seen[0].decode()
    assert request.startswith("POST /in?x=1 ")
    assert f"Host: hook.invalid:{srv.port}" in request


def test_total_deadline_stops_a_receiver_that_drips_its_answer(server):
    def drip(conn, seen):
        _read_request(conn)
        for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 100:
            conn.sendall(bytes([byte]))
            time.sleep(0.3)  # each single read is fast; the whole answer never ends

    srv = server(drip)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        pinned_post.post(f"http://hook.invalid:{srv.port}/", "127.0.0.1", b"{}", {}, total_timeout=1.0)
    assert time.monotonic() - started < 3


def test_response_body_is_never_read(server):
    def huge(conn, seen):
        _read_request(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n")
        time.sleep(5)  # promises a gigabyte and then sends nothing

    srv = server(huge)
    started = time.monotonic()
    status = pinned_post.post(f"http://hook.invalid:{srv.port}/", "127.0.0.1", b"{}", {}, total_timeout=3)
    assert status == 200 and time.monotonic() - started < 2


def test_unsupported_scheme_is_rejected():
    with pytest.raises(ValueError):
        pinned_post.post("ftp://hook.example.org/", "93.184.216.34", b"", {})
