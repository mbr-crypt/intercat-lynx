"""
Admin-only endpoints for system management.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..dependencies.auth import require_admin
from ..models import User, Vulnerability
from ..services import audit_service, import_job, task_activity

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats")
async def get_system_stats(
    current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    Get system statistics (Admin only).

    **Requires:** Admin role

    **Returns:**
    - Total users
    - Total vulnerabilities
    - System health metrics
    """
    total_users = db.query(func.count(User.id)).scalar()
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
    total_vulns = db.query(func.count(Vulnerability.id)).scalar()

    logger.info(f"Admin {current_user.username} accessed system stats")

    return {
        "users": {
            "total": total_users,
            "active": active_users,
            "inactive": total_users - active_users,
        },
        "vulnerabilities": {"total": total_vulns},
        "system": {"status": "healthy"},
    }


@router.delete("/vulnerabilities/{vuln_id}")
async def delete_vulnerability(
    vuln_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Delete a vulnerability (Admin only).

    **Requires:** Admin role

    **Warning:** This is a destructive operation!

    **Returns:**
    - Success message
    """
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found"
        )

    cve_id = vuln.cve_id
    db.delete(vuln)
    db.commit()

    logger.warning(f"Admin {current_user.username} deleted vulnerability {cve_id}")

    return {
        "message": f"Vulnerability {cve_id} deleted successfully",
        "deleted_by": current_user.username,
    }


# --------------------------------------------------------------------------
# Background activity (what the system is doing right now)
# --------------------------------------------------------------------------


class ImportRequest(BaseModel):
    mode: str = Field(..., pattern="^(recent|full)$")
    days: int = Field(default=7, ge=1, le=120)
    # Continue an interrupted import where it stopped (mode and days then come from it)
    resume: bool = False


def _import_title(state: dict) -> str:
    if state.get("mode") == "full":
        return "Datenimport, kompletter Bestand"
    days = state.get("days")
    return f"Datenimport, letzte {days} Tage" if days else "Datenimport"


@router.get("/activity")
async def get_activity(
    current_user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """
    What the system does in the background right now (Admin only).

    ``activities`` is the data import (the part that has a progress display).
    ``scheduled`` is the last run of every scheduled Celery task (NVD, CISA KEV,
    alerts, statistics, news ...), written by the worker, see ``task_activity``.

    **Requires:** Admin role
    """
    activities = []
    state = import_job.read_status(db)
    if state.get("state") != "idle":
        activities.append({"id": "import", "title": _import_title(state), **state})
    return {
        "activities": activities,
        "running": any(a["state"] == "running" for a in activities),
        "scheduled": task_activity.read_all(db),
    }


@router.post("/import")
async def start_import(
    data: ImportRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Start a data import from the NVD (Admin only), for example to fill up an
    installation after the setup assistant is closed.

    **Requires:** Admin role
    """
    mode, days, checkpoint = data.mode, data.days, None
    if data.resume:
        point = import_job.resume_point(db)
        if point is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Es gibt keinen unterbrochenen Import zum Fortsetzen",
            )
        mode, days, checkpoint = point["mode"], point["days"], point["checkpoint"]
    if not import_job.start_in_background(SessionLocal, mode, days, resume=checkpoint):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Ein Import läuft bereits"
        )
    audit_service.record(
        db,
        current_user,
        audit_service.IMPORT_STARTED,
        detail=f"mode={mode} days={days}" + (" resumed" if checkpoint else ""),
    )
    return {"started": True}
