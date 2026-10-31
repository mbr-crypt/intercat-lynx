"""
Prometheus metrics middleware for OpenThreat.

Collects and exposes metrics for monitoring.
"""

import logging
import time

from fastapi import Request
from fastapi.responses import Response as FastAPIResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger(__name__)

# Request metrics
http_requests_total = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)

http_requests_in_progress = Gauge(
    "http_requests_in_progress", "HTTP requests currently in progress"
)

# Application metrics
vulnerabilities_total = Gauge(
    "vulnerabilities_total", "Total number of vulnerabilities in database"
)

exploited_vulnerabilities_total = Gauge(
    "exploited_vulnerabilities_total", "Total number of exploited vulnerabilities"
)

# Error metrics
http_errors_total = Counter(
    "http_errors_total", "Total HTTP errors", ["method", "endpoint", "status"]
)


UNMATCHED = "unmatched"


def _endpoint_label(request: Request) -> str:
    """
    The route *template* with its router prefix, e.g.
    ``/api/v1/vulnerabilities/{cve_id}``, never the raw URL.

    Every distinct label value creates a new time series that lives in memory
    until the process restarts. With the raw path an anonymous caller could
    request ``/x1``, ``/x2``, ... and grow the metrics without limit
    (cardinality explosion). Requests that match no route share one label.

    Newer FastAPI versions put only the route's own part into ``route.path``
    (``/vulnerabilities/{cve_id}``, or even an empty string for a list route),
    without the prefix of the router it was included with. The prefix is
    recovered from the real path: the real path is ``prefix + concrete route
    part``, and the concrete route part is the template filled with the matched
    path parameters.
    """
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str):
        return UNMATCHED
    path = request.url.path
    try:
        concrete = getattr(route, "path_format", template).format(
            **request.scope.get("path_params", {})
        )
    except (KeyError, IndexError, ValueError):
        return template or UNMATCHED
    if concrete and path.endswith(concrete):
        return path[: -len(concrete)] + template
    if not concrete:
        # empty route part: the whole path is the (fixed) router prefix
        return path or UNMATCHED
    return template


async def metrics_middleware(request: Request, call_next):
    """
    Middleware to collect Prometheus metrics.

    Args:
        request: FastAPI request
        call_next: Next middleware/handler

    Returns:
        Response with metrics collected
    """
    # Skip metrics collection for metrics endpoint itself
    if request.url.path == "/metrics":
        return await call_next(request)

    # Track in-progress requests
    http_requests_in_progress.inc()

    # Record start time
    start_time = time.time()

    try:
        # Process request
        response = await call_next(request)

        # Record metrics
        duration = time.time() - start_time
        endpoint = _endpoint_label(request)

        http_requests_total.labels(
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
        ).inc()

        http_request_duration_seconds.labels(
            method=request.method, endpoint=endpoint
        ).observe(duration)

        # Track errors
        if response.status_code >= 400:
            http_errors_total.labels(
                method=request.method,
                endpoint=endpoint,
                status=response.status_code,
            ).inc()

        return response

    finally:
        # Decrement in-progress counter
        http_requests_in_progress.dec()


def update_application_metrics(db_session):
    """
    Update application-specific metrics.

    Args:
        db_session: Database session
    """
    try:
        from backend.models import Vulnerability

        # Update vulnerability counts
        total = db_session.query(Vulnerability).count()
        exploited = (
            db_session.query(Vulnerability)
            .filter(Vulnerability.exploited_in_the_wild == True)
            .count()
        )

        vulnerabilities_total.set(total)
        exploited_vulnerabilities_total.set(exploited)

    except Exception as e:
        logger.error(f"Failed to update application metrics: {e}")


async def metrics_endpoint(request: Request):
    """
    Prometheus metrics endpoint.

    Args:
        request: FastAPI request

    Returns:
        Prometheus metrics in text format
    """
    # Update application metrics before exposing
    try:
        from backend.database import get_db

        db = next(get_db())
        try:
            update_application_metrics(db)
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Could not update metrics: {e}")

    # Generate and return metrics
    metrics_data = generate_latest()

    return FastAPIResponse(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
