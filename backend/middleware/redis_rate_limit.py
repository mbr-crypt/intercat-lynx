"""
Redis-based distributed rate limiting middleware.

Supports multiple backend replicas by using Redis as shared state.
"""

import logging
import os
from datetime import datetime
from typing import Tuple

import redis
from fastapi import Request, status
from fastapi.responses import JSONResponse
from ..utils.client_ip import get_client_ip

logger = logging.getLogger(__name__)


# Status pages poll their endpoint every few seconds while an import runs. They get a
# budget of their own, otherwise a single open browser tab would use up the limit of the
# whole address (and with it the login). The endpoints are cheap reads; unauthenticated
# calls are rejected before any work is done.
STATUS_PATHS = {"/api/v1/admin/activity", "/api/v1/setup/import/status"}
STATUS_BUCKET = "status"


class RedisRateLimiter:
    """
    Distributed rate limiter using Redis.

    Works across multiple backend instances/replicas.
    """

    def __init__(
        self,
        redis_url: str,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        status_per_minute: int = 120,
        status_per_hour: int = 4000,
    ):
        """
        Initialize Redis rate limiter.

        Args:
            redis_url: Redis connection URL
            requests_per_minute: Maximum requests per minute per IP
            requests_per_hour: Maximum requests per hour per IP
        """
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.status_per_minute = status_per_minute
        self.status_per_hour = status_per_hour

        # Test Redis connection. A missing Redis must not stop the app from
        # importing/starting: check_rate_limit() already fails open on Redis
        # errors, so we only warn here (this also lets the test suite and local
        # development run without a Redis server).
        try:
            self.redis_client.ping()
            logger.info("Redis rate limiter connected successfully")
        except redis.ConnectionError as e:
            logger.warning(
                f"Redis not reachable, rate limiting will fail open until it is: {e}"
            )

    def check_rate_limit(self, ip: str, bucket: str = "") -> Tuple[bool, str, dict]:
        """
        Check if IP has exceeded rate limit using Redis.

        Args:
            ip: Client IP address
            bucket: "" for the general budget, STATUS_BUCKET for status polling

        Returns:
            Tuple of (is_allowed, error_message, rate_limit_info)
        """
        now = datetime.now()
        prefix = f"rate_limit:{bucket}:{ip}" if bucket else f"rate_limit:{ip}"
        minute_key = f"{prefix}:minute:{now.strftime('%Y%m%d%H%M')}"
        hour_key = f"{prefix}:hour:{now.strftime('%Y%m%d%H')}"
        per_minute, per_hour = self.requests_per_minute, self.requests_per_hour
        if bucket == STATUS_BUCKET:
            per_minute, per_hour = self.status_per_minute, self.status_per_hour

        try:
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()

            # Increment and get minute counter
            pipe.incr(minute_key)
            pipe.expire(minute_key, 60)  # Expire after 60 seconds

            # Increment and get hour counter
            pipe.incr(hour_key)
            pipe.expire(hour_key, 3600)  # Expire after 1 hour

            results = pipe.execute()

            minute_count = results[0]
            hour_count = results[2]

            # Calculate remaining requests
            minute_remaining = max(0, per_minute - minute_count)
            hour_remaining = max(0, per_hour - hour_count)

            rate_limit_info = {
                "limit_minute": per_minute,
                "limit_hour": per_hour,
                "remaining_minute": minute_remaining,
                "remaining_hour": hour_remaining,
                "used_minute": minute_count,
                "used_hour": hour_count,
            }

            # Check limits
            if minute_count > per_minute:
                return (
                    False,
                    f"Rate limit exceeded: {per_minute} requests per minute",
                    rate_limit_info,
                )

            if hour_count > per_hour:
                return (
                    False,
                    f"Rate limit exceeded: {per_hour} requests per hour",
                    rate_limit_info,
                )

            return True, "", rate_limit_info

        except redis.RedisError as e:
            logger.error(f"Redis error in rate limiting: {e}")
            # Fail open - allow request if Redis is down
            return (
                True,
                "",
                {
                    "limit_minute": per_minute,
                    "limit_hour": per_hour,
                    "remaining_minute": per_minute,
                    "remaining_hour": per_hour,
                    "error": "rate_limiter_unavailable",
                },
            )

    def get_client_ip(self, request: Request) -> str:
        """Client address behind our proxy, see ``utils/client_ip.py`` for the rules."""
        return get_client_ip(request)

    def is_whitelisted(self, ip: str) -> bool:
        """
        Check if IP is whitelisted (bypass rate limiting).

        Args:
            ip: IP address to check

        Returns:
            True if whitelisted
        """
        # Get whitelist from environment variable
        whitelist = os.getenv("RATE_LIMIT_WHITELIST", "").split(",")
        whitelist = [ip.strip() for ip in whitelist if ip.strip()]

        return ip in whitelist


# Global rate limiter instance
from backend.database import REDIS_URL

redis_rate_limiter = RedisRateLimiter(
    redis_url=REDIS_URL,
    requests_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
    requests_per_hour=int(os.getenv("RATE_LIMIT_PER_HOUR", "1000")),
    status_per_minute=int(os.getenv("RATE_LIMIT_STATUS_PER_MINUTE", "120")),
    status_per_hour=int(os.getenv("RATE_LIMIT_STATUS_PER_HOUR", "4000")),
)


async def redis_rate_limit_middleware(request: Request, call_next):
    """
    Redis-based rate limiting middleware for FastAPI.

    Args:
        request: FastAPI request
        call_next: Next middleware/handler

    Returns:
        Response or rate limit error
    """
    # Skip rate limiting for health checks and docs
    skip_paths = ["/health", "/", "/docs", "/redoc", "/openapi.json", "/metrics"]
    if request.url.path in skip_paths:
        return await call_next(request)

    # Get client IP
    client_ip = redis_rate_limiter.get_client_ip(request)

    # Check if IP is whitelisted
    if redis_rate_limiter.is_whitelisted(client_ip):
        response = await call_next(request)
        response.headers["X-RateLimit-Bypass"] = "whitelisted"
        return response

    # Check rate limit
    bucket = STATUS_BUCKET if request.url.path in STATUS_PATHS else ""
    is_allowed, error_message, rate_info = redis_rate_limiter.check_rate_limit(
        client_ip, bucket
    )

    if not is_allowed:
        logger.warning(
            f"Rate limit exceeded for IP: {client_ip}",
            extra={
                "ip": client_ip,
                "path": request.url.path,
                "used_minute": rate_info.get("used_minute"),
                "used_hour": rate_info.get("used_hour"),
            },
        )

        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": error_message,
                "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
                "details": {
                    "retry_after": "60 seconds",
                    "limits": {
                        "per_minute": rate_info["limit_minute"],
                        "per_hour": rate_info["limit_hour"],
                    },
                    "remaining": {
                        "per_minute": rate_info["remaining_minute"],
                        "per_hour": rate_info["remaining_hour"],
                    },
                },
            },
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit-Minute": str(rate_info["limit_minute"]),
                "X-RateLimit-Limit-Hour": str(rate_info["limit_hour"]),
                "X-RateLimit-Remaining-Minute": str(rate_info["remaining_minute"]),
                "X-RateLimit-Remaining-Hour": str(rate_info["remaining_hour"]),
            },
        )

    # Process request
    response = await call_next(request)

    # Add rate limit headers to response
    response.headers["X-RateLimit-Limit-Minute"] = str(rate_info["limit_minute"])
    response.headers["X-RateLimit-Limit-Hour"] = str(rate_info["limit_hour"])
    response.headers["X-RateLimit-Remaining-Minute"] = str(
        rate_info["remaining_minute"]
    )
    response.headers["X-RateLimit-Remaining-Hour"] = str(rate_info["remaining_hour"])

    return response
