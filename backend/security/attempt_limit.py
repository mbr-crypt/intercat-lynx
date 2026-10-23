"""
Counters that limit how often something may happen within a time window.

Used for the e-mail codes: a six-digit code has only a million possibilities,
so guessing has to be capped per e-mail address (and per client address), and
sending codes has to be capped as well, otherwise the endpoint can be used to
flood a stranger's mailbox.

Counts live in Redis (shared by all backend processes) and fall back to
process memory if Redis is down. Failing open is deliberate: a Redis outage
must not make registration impossible.
"""

import logging
import time
from typing import Dict, Optional, Tuple

import redis
from fastapi import HTTPException, status

from ..database import REDIS_URL

logger = logging.getLogger(__name__)

# Set False in tests so they never depend on a running Redis
USE_REDIS = True

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
    logger.warning("Attempt limiter: Redis unavailable, using memory (%s)", error)


class AttemptLimiter:
    """At most ``max_attempts`` events per key within ``window_seconds``."""

    def __init__(self, name: str, max_attempts: int, window_seconds: int, message: str):
        self.name = name
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.message = message
        self._memory: Dict[str, Tuple[int, float]] = {}

    def _key(self, key: str) -> str:
        return f"attempts:{self.name}:{key.lower()}"

    def _memory_count(self, key: str) -> int:
        count, expires = self._memory.get(key, (0, 0.0))
        if expires < time.time():
            self._memory.pop(key, None)
            return 0
        return count

    def count(self, key: str) -> int:
        client = _redis()
        if client is not None:
            try:
                return int(client.get(self._key(key)) or 0)
            except redis.RedisError as e:
                _redis_failed(e)
        return self._memory_count(self._key(key))

    def record(self, key: str) -> None:
        full = self._key(key)
        client = _redis()
        if client is not None:
            try:
                if client.incr(full) == 1:
                    client.expire(full, self.window_seconds)
                return
            except redis.RedisError as e:
                _redis_failed(e)
        count = self._memory_count(full)
        expires = self._memory[full][1] if full in self._memory else time.time() + self.window_seconds
        self._memory[full] = (count + 1, expires)
        if len(self._memory) > 10000:  # a flood of keys must not eat memory
            for k in [k for k, (_, exp) in self._memory.items() if exp < time.time()]:
                self._memory.pop(k, None)

    def check(self, key: str) -> None:
        """Raise 429 if the key has used up its attempts."""
        if self.count(key) >= self.max_attempts:
            logger.warning("%s limit reached for %s", self.name, key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=self.message,
                headers={"Retry-After": str(self.window_seconds)},
            )

    def reset(self, key: str) -> None:
        full = self._key(key)
        self._memory.pop(full, None)
        client = _redis()
        if client is not None:
            try:
                client.delete(full)
            except redis.RedisError as e:
                _redis_failed(e)

    def clear_memory(self) -> None:
        """For tests."""
        self._memory.clear()


# Wrong codes, per e-mail address and per client address
code_failures_by_email = AttemptLimiter(
    "code_fail_email", 5, 15 * 60,
    "Too many wrong codes. Request a new code and try again later.",
)
code_failures_by_ip = AttemptLimiter(
    "code_fail_ip", 20, 15 * 60,
    "Too many wrong codes from your address. Try again later.",
)
# Codes sent, per e-mail address and per client address
code_sends_by_email = AttemptLimiter(
    "code_send_email", 3, 15 * 60,
    "A code was sent recently. Check your inbox or try again in a few minutes.",
)
code_sends_by_ip = AttemptLimiter(
    "code_send_ip", 10, 60 * 60,
    "Too many codes requested from your address. Try again later.",
)

ALL = [code_failures_by_email, code_failures_by_ip, code_sends_by_email, code_sends_by_ip]


def reset_all_memory() -> None:
    """For tests."""
    for limiter in ALL:
        limiter.clear_memory()
