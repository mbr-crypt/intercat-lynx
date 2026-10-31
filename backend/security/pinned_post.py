"""
One outgoing HTTP POST to an address that was checked beforehand.

Why this exists instead of ``requests.post(url)``:

* **DNS pinning.** The webhook check resolves the host name and rejects internal
  addresses. ``requests`` would then resolve the name *again* when it connects.
  A hostile DNS server can answer the first question with a public address and
  the second one with ``127.0.0.1`` (DNS rebinding). Here the connection goes
  to the IP address that was validated; the host name is only used for the
  ``Host`` header and for TLS (SNI and certificate check), so HTTPS stays
  verified.
* **One total deadline.** ``timeout=10`` in ``requests`` is per socket
  operation, not for the whole request. A receiver that sends one byte every
  few seconds keeps the call alive for as long as it likes. A timer here closes
  the socket when the total time is used up.
* **No response body.** Only the status line is needed. Never reading the body
  means a huge or endless answer cannot cost time or memory.
* **No redirects**, since a redirect would lead to an address nobody checked.
"""

import http.client
import socket
import ssl
import threading
from typing import Dict
from urllib.parse import urlparse

TOTAL_TIMEOUT = 10.0  # seconds for connect + send + reading the status line


class _Pinned(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        # server_hostname: SNI and certificate name check use the host *name*
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def post(
    url: str,
    ip: str,
    body: bytes,
    headers: Dict[str, str],
    total_timeout: float = TOTAL_TIMEOUT,
) -> int:
    """
    POST ``body`` to ``url`` over a connection to ``ip`` and return the HTTP status.

    Raises ``TimeoutError`` when ``total_timeout`` is used up, and ``OSError`` /
    ``http.client.HTTPException`` for other transport problems.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("unsupported URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    factory = _PinnedTLS if parsed.scheme == "https" else _Pinned
    conn = factory(host, port, ip, total_timeout)

    expired = threading.Event()

    def _expire():
        expired.set()
        sock = conn.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    timer = threading.Timer(total_timeout, _expire)
    timer.daemon = True
    timer.start()
    try:
        try:
            conn.request("POST", path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status
        except (OSError, http.client.HTTPException) as exc:
            if expired.is_set():
                raise TimeoutError("total deadline exceeded") from exc
            raise
    finally:
        timer.cancel()
        conn.close()
