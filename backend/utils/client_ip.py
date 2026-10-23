"""
The IP address of the client behind our own reverse proxy (nginx).

Why this is not just "the first entry of X-Forwarded-For"
--------------------------------------------------------
A client can send its own ``X-Forwarded-For`` header. nginx *appends* the
address it really saw to it (``$proxy_add_x_forwarded_for``), so the header
arrives as ``<whatever the client wrote>, <real address>``. Taking the first
entry therefore lets anyone choose the address that rate limits and lockouts
are counted against, and a different one for every request.

The only entries that can be trusted are the ones added by our own proxies,
and those are at the **end** of the list. ``TRUSTED_PROXIES`` says how many
proxies of ours sit in front of the backend (the Docker setup has one: nginx):

* ``0`` (default): no proxy, the header is ignored, the address of the TCP
  connection is used. Right for development and for direct exposure.
* ``1``: the last entry was written by nginx and is the client. If nginx sits
  behind another proxy (Cloudflare, a load balancer), set ``2``; then the
  second-to-last entry is used.

The backend port must never be reachable from outside when this is on: whoever
can talk to the backend directly can write the whole header.
"""

import ipaddress
import os
from typing import Optional

from starlette.requests import Request

MAX_PROXIES = 10


def trusted_proxy_count() -> int:
    try:
        value = int(os.getenv("TRUSTED_PROXIES", "0"))
    except ValueError:
        return 0
    return max(0, min(value, MAX_PROXIES))


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def get_client_ip(request: Request) -> str:
    """Address used for rate limits and lockouts. Never raises."""
    peer = request.client.host if request.client else "unknown"
    proxies = trusted_proxy_count()
    if proxies == 0:
        return peer

    header = request.headers.get("x-forwarded-for", "")
    entries = [part.strip() for part in header.split(",") if part.strip()]
    if len(entries) < proxies:
        # Fewer hops than configured: the request did not come through the
        # proxy chain (or the configuration is wrong). Trust nothing.
        return peer
    return _valid_ip(entries[-proxies]) or peer
