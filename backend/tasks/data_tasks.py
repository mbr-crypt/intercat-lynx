"""
Celery tasks for data fetching and enrichment.

This module handles background tasks for:
- Fetching CISA KEV data
- Updating vulnerability exploitation status
"""

import logging
from datetime import datetime

from backend.celery_app import celery_app as celery
from backend.services.task_activity import tracked
from backend.database import get_db
from backend.services.cisa_kev_service import get_cisa_kev_service
from backend.services.nvd_complete_service import get_nvd_service
from backend.services.stats_cache_service import refresh_stats_cache

logger = logging.getLogger(__name__)


@celery.task(name="tasks.fetch_cisa_kev", bind=True, max_retries=3)
@tracked("fetch-cisa-kev")
def fetch_cisa_kev_task(self) -> dict:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.

    This task:
    1. Fetches the latest CISA KEV catalog
    2. Marks CVEs as exploited in the wild
    3. Updates priority scores
    4. Adds CISA KEV as a source

    Returns:
        Dict with status and results
    """
    db = next(get_db())
    try:
        logger.info("Starting CISA KEV fetch task")

        # Get CISA KEV service
        kev_service = get_cisa_kev_service()

        # Fetch and update
        result = kev_service.update_exploited_vulnerabilities(db)

        if result["status"] == "success":
            logger.info(
                f"CISA KEV task complete: {result['updated']} vulnerabilities updated"
            )
        else:
            logger.warning(f"CISA KEV task completed with warnings: {result}")

        return result

    except Exception as e:
        db.rollback()
        logger.error(f"CISA KEV task failed: {e}")

        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2**self.request.retries))

    finally:
        db.close()


@celery.task(name="tasks.refresh_stats_cache")
@tracked("refresh-stats-cache")
def refresh_stats_cache_task() -> dict:
    """
    Refresh vulnerability statistics cache.

    This task should run periodically (e.g., every 5 minutes) to ensure
    stats are always up-to-date, even if the automatic refresh after
    data ingestion fails.

    Returns:
        Dict with status
    """
    db = next(get_db())
    try:
        logger.info("Starting stats cache refresh task")

        success = refresh_stats_cache(db)

        if success:
            logger.info("Stats cache refresh task complete")
            return {
                "status": "success",
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            logger.warning("Stats cache refresh task completed with errors")
            return {
                "status": "error",
                "message": "Failed to refresh stats cache",
                "timestamp": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        logger.error(f"Stats cache refresh task failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }

    finally:
        db.close()


@celery.task(name="tasks.fetch_nvd_recent", bind=True, max_retries=3)
@tracked("fetch-nvd-recent")
def fetch_nvd_recent_task(self, days: int = 1) -> dict:
    """
    Fetch recent CVEs from NVD (modified in last N days).

    This task should run daily to keep CVE data up-to-date.
    It fetches CVEs that were published or modified recently.

    Args:
        days: Number of days to look back (default: 1)

    Returns:
        Dict with status and results
    """
    try:
        logger.info(f"Starting NVD recent fetch task (last {days} days)")

        # Get NVD service
        nvd_service = get_nvd_service()

        # Fetch recent CVEs
        count = nvd_service.fetch_recent_cves(days=days)

        logger.info(f"NVD recent fetch complete: {count} CVEs processed")

        return {
            "status": "success",
            "cves_processed": count,
            "days": days,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"NVD recent fetch task failed: {e}")

        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=300 * (2**self.request.retries))


@celery.task(name="tasks.rebuild_product_catalog")
@tracked("rebuild-product-catalog")
def rebuild_product_catalog_task() -> dict:
    """Recount the vendor/product list the product picker searches in."""
    from backend.services.watchlist_service import rebuild_catalog

    db = next(get_db())
    try:
        result = rebuild_catalog(db)
        return {"status": "success", **result}
    except Exception as e:  # noqa: BLE001
        logger.error("Product catalog rebuild failed: %s", e)
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery.task(name="tasks.send_product_alerts")
@tracked("send-product-alerts")
def send_product_alerts_task() -> dict:
    """Send alerts (in-app, e-mail, webhook) for CVEs concerning followed products."""
    from backend.services import product_alert_service

    db = next(get_db())
    try:
        return {"status": "success", **product_alert_service.run(db)}
    except Exception as e:  # noqa: BLE001
        logger.error("Product alert run failed: %s: %s", type(e).__name__, e)
        return {"status": "error", "message": f"{type(e).__name__}"}
    finally:
        db.close()
