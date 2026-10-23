"""
Failed-login counter per client address.

Why it exists: the account lockout alone (5 wrong passwords lock the account)
can be turned into a weapon, because anyone who knows a username can lock that
person out. The lockout therefore only applies to addresses the user did not
log in from last (see ``api/auth.py``). This counter is the other half: one
address can only make a limited number of failed attempts in total, whatever
usernames it tries. That stops password spraying across many accounts and
locking many accounts from one place.

Counts live in Redis (shared by all backend processes) and fall back to
process memory if Redis is down. Failing open is deliberate: a Redis outage
must not lock everybody out of the application.
"""

import logging
import time
from typing import Dict, Optional, Tuple

import redis
from fastapi import HTTPException, status

from ..database import REDIS_URL

logger = logging.getLogger(__name__)

MAX_FAILURES = 20
WINDOW_SECONDS = 15 * 60
KEY_PREFIX = "login_fail:"

# Set False in tests so they never depend on a running Redis
USE_REDIS = True

_memory: Dict[str, Tuple[int, float]] = {}
_client: Optional["redis.Redis"] = None
_redis_down_until = 0.0


def _redis() -> Optional["redis.Redis"]:
    global _client, _redis_down_until
    if not USE_REDIS or time.time() < _redis_down_until:
        return None
    if _client is None:
        _client = redis.from_url(
            REDIS_URL, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5
        )
    return _client


def _redis_failed(error: Exception) -> None:
    global _redis_down_until
    _redis_down_until = time.time() + 30  # do not retry on every request
    logger.warning("Login throttle: Redis unavailable, using memory (%s)", error)


def _memory_count(ip: str) -> int:
    count, expires = _memory.get(ip, (0, 0.0))
    if expires < time.time():
        _memory.pop(ip, None)
        return 0
    return count


def failures(ip: str) -> int:
    client = _redis()
    if client is not None:
        try:
            return int(client.get(KEY_PREFIX + ip) or 0)
        except redis.RedisError as e:
            _redis_failed(e)
    return _memory_count(ip)


def record_failure(ip: str) -> None:
    client = _redis()
    if client is not None:
        try:
            key = KEY_PREFIX + ip
            if client.incr(key) == 1:
                client.expire(key, WINDOW_SECONDS)
            return
        except redis.RedisError as e:
            _redis_failed(e)
    count = _memory_count(ip)
    expires = _memory[ip][1] if ip in _memory else time.time() + WINDOW_SECONDS
    _memory[ip] = (count + 1, expires)
    if len(_memory) > 10000:  # a flood of addresses must not eat memory
        for key in [k for k, (_, exp) in _memory.items() if exp < time.time()]:
            _memory.pop(key, None)


def check(ip: str) -> None:
    """Raise 429 if this address already failed too often."""
    if failures(ip) >= MAX_FAILURES:
        logger.warning("Login blocked, too many failed attempts from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts from your address. Try again later.",
            headers={"Retry-After": str(WINDOW_SECONDS)},
        )


def reset_memory() -> None:
    """For tests."""
    _memory.clear()
