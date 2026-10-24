"""
CISA Known Exploited Vulnerabilities (KEV) Service.

Fetches and processes the CISA KEV catalog to mark vulnerabilities
as exploited in the wild using the NVD API.
"""

import logging
import time
from datetime import datetime
from typing import Dict, List

import requests
from sqlalchemy.orm import Session

from backend.models import Vulnerability
from backend.services.nvd_complete_service import NVDCompleteService
from backend.services.stats_cache_service import refresh_stats_cache

logger = logging.getLogger(__name__)


class CISAKEVService:
    """Service for fetching and processing CISA KEV data via NVD API."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.nvd_service = NVDCompleteService()
        #   event_callback(text) - one line for the visible event log of the import
        self.event_callback = None

    def _event(self, text: str) -> None:
        logger.info(text)
        if self.event_callback:
            try:
                self.event_callback(text)
            except Exception:  # noqa: BLE001 - best effort
                pass

    def fetch_kev_cves(self) -> List[Dict]:
        """
        Fetch all CVEs marked as KEV from NVD API.

        Returns:
            List of CVE records with KEV status
        """
        all_cves = []
        start_index = 0
        results_per_page = 2000  # Maximum allowed by NVD API

        headers = {
            "User-Agent": "InterCat-Lynx/0.1 (fork of OpenThreat; vulnerability management)",
            "Accept": "application/json",
        }
        if self.nvd_service.api_key:
            headers["apiKey"] = self.nvd_service.api_key

        self._event("Liste der aktiv ausgenutzten Lücken wird bei der NVD abgefragt")

        while True:
            try:
                # Use hasKev parameter to get only KEV CVEs
                url = f"{self.NVD_API_BASE}?hasKev&resultsPerPage={results_per_page}&startIndex={start_index}"

                logger.info(f"Requesting CVEs from index {start_index}...")
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                all_cves.extend(vulnerabilities)
                logger.info(
                    f"Fetched {len(vulnerabilities)} CVEs (total: {len(all_cves)}/{total_results})"
                )

                # Check if we've fetched all results
                if len(all_cves) >= total_results:
                    break

                start_index += results_per_page

                # Rate limiting: wait between two requests (6 s without API key)
                time.sleep(self.nvd_service.rate_limit_delay)

            except Exception as e:
                logger.error(f"Failed to fetch KEV CVEs from NVD: {e}")
                self._event(f"CISA-KEV-Abfrage fehlgeschlagen ({type(e).__name__})")
                break

        logger.info(f"Successfully fetched {len(all_cves)} KEV CVEs from NVD")
        return all_cves

    def update_exploited_vulnerabilities(self, db: Session, create_missing: bool = True) -> Dict:
        """
        Update database with CISA KEV data from NVD API.

        The NVD answers the KEV query with the complete records of these CVEs.
        CVEs that are not in the database yet (for example because only the last
        days were imported) are created from exactly this answer, so no further
        request is needed.

        Args:
            db: Database session
            create_missing: Create CVEs of the KEV list that the database lacks

        Returns:
            Dict with update statistics
        """
        kev_cves = self.fetch_kev_cves()

        if not kev_cves:
            return {
                "status": "error",
                "message": "Failed to fetch CISA KEV data from NVD",
                "updated": 0,
                "created": 0,
                "not_found": 0,
            }

        self._event(f"{len(kev_cves)} Einträge in der KEV-Liste, werden abgeglichen")

        updated_count = 0
        created_count = 0
        not_found_count = 0

        for vuln_wrapper in kev_cves:
            cve_data = vuln_wrapper.get("cve", {})
            cve_id = cve_data.get("id")

            if not cve_id:
                continue

            # Find CVE in database
            existing = (
                db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
            )

            if existing is None:
                not_found_count += 1
                if create_missing:
                    existing = self.nvd_service._process_cve(db, vuln_wrapper, existing=None)
                    if existing is not None:
                        created_count += 1

            if existing:
                # Mark as exploited
                existing.exploited_in_the_wild = True

                # Add CISA source if not present
                sources = list(existing.sources or [])
                if "cisa_kev" not in sources:
                    sources.append("cisa_kev")
                    existing.sources = sources

                # Recalculate priority (exploitation increases priority)
                published = existing.published_at
                existing.priority_score = self.nvd_service._calculate_priority(
                    existing.cvss_score,
                    existing.severity,
                    (
                        published
                        if isinstance(published, str)
                        else published.isoformat() if published else None
                    ),
                    exploited=True,
                )

                updated_count += 1

                if updated_count % 100 == 0:
                    logger.info(f"Updated {updated_count} CVEs...")
                    db.commit()  # Commit in batches

        # Final commit
        db.commit()

        # Refresh stats cache after KEV updates
        # Always refresh to keep time-sensitive stats (like recent updates) accurate
        refresh_stats_cache(db)

        logger.info(
            f"CISA KEV update complete: {updated_count} updated "
            f"({created_count} newly created), {not_found_count} were not in the database"
        )

        return {
            "status": "success",
            "total_kev_entries": len(kev_cves),
            "updated": updated_count,
            "created": created_count,
            "not_found": not_found_count,
            "timestamp": datetime.utcnow().isoformat(),
        }


def get_cisa_kev_service() -> CISAKEVService:
    """Get CISA KEV service instance."""
    return CISAKEVService()
