"""
BSI CERT-Bund warnings.

Public reading (list, lookup by CVE) for the "BSI" page and the badge on the CVE
page; switch, status and manual fetch are for administrators only. Every
answer carries the link to the original at the BSI.
"""

import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import require_admin
from ..models import BsiAdvisory, BsiAdvisoryCve, User
from ..services import audit_service, bsi_service, settings_service

router = APIRouter()

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITY_ORDER = ["kritisch", "hoch", "mittel", "niedrig"]


class AdvisoryOut(BaseModel):
    advisory_id: str
    title: str
    severity: Optional[str]
    published_at: Optional[datetime]
    updated_at: Optional[datetime]
    url: str
    products: List[str]
    cve_count: int
    cves: List[str]


class AdvisoryPage(BaseModel):
    items: List[AdvisoryOut]
    total: int
    page: int
    page_size: int
    source: str = "Bundesamt für Sicherheit in der Informationstechnik (BSI), CERT-Bund"


class BsiSettingsIn(BaseModel):
    enabled: bool


def _out(row: BsiAdvisory, cves: Optional[List[str]] = None) -> AdvisoryOut:
    return AdvisoryOut(
        advisory_id=row.advisory_id,
        title=row.title,
        severity=row.severity,
        published_at=row.published_at,
        updated_at=row.updated_at,
        url=row.url,
        products=list(row.products or []),
        cve_count=row.cve_count or 0,
        cves=cves if cves is not None else [c.cve_id for c in row.cves][:30],
    )


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/advisories", response_model=AdvisoryPage)
def list_advisories(
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(25, ge=1, le=100),
    severity: Optional[str] = Query(None, max_length=20),
    q: Optional[str] = Query(None, max_length=100),
    db: Session = Depends(get_db),
):
    query = db.query(BsiAdvisory)
    if severity:
        if severity.lower() not in SEVERITY_ORDER:
            raise HTTPException(status_code=422, detail="Unbekannte Einstufung")
        query = query.filter(BsiAdvisory.severity == severity.lower())
    if q and q.strip():
        term = q.strip()
        pattern = _like(term)
        conditions = [
            BsiAdvisory.title.ilike(pattern, escape="\\"),
            BsiAdvisory.advisory_id.ilike(pattern, escape="\\"),
        ]
        if CVE_RE.match(term.upper()):
            conditions.append(
                BsiAdvisory.id.in_(
                    db.query(BsiAdvisoryCve.advisory_id).filter(
                        BsiAdvisoryCve.cve_id == term.upper()
                    )
                )
            )
        query = query.filter(or_(*conditions))
    total = query.count()
    rows = (
        query.order_by(BsiAdvisory.updated_at.desc().nullslast(), BsiAdvisory.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AdvisoryPage(items=[_out(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/cve/{cve_id}", response_model=List[AdvisoryOut])
def advisories_for_cve(cve_id: str, db: Session = Depends(get_db)):
    cve = cve_id.strip().upper()
    if not CVE_RE.match(cve):
        raise HTTPException(status_code=422, detail="Ungültige CVE-Nummer")
    rows = (
        db.query(BsiAdvisory)
        .join(BsiAdvisoryCve, BsiAdvisoryCve.advisory_id == BsiAdvisory.id)
        .filter(BsiAdvisoryCve.cve_id == cve)
        .order_by(BsiAdvisory.updated_at.desc().nullslast())
        .limit(20)
        .all()
    )
    return [_out(r, cves=[cve]) for r in rows]


@router.get("/status")
def bsi_status(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return bsi_service.status(db)


@router.put("/settings")
def set_enabled(
    data: BsiSettingsIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    settings_service.set_value(db, bsi_service.KEY_ENABLED, "true" if data.enabled else "false")
    audit_service.record(
        db,
        current_user,
        audit_service.SETTING_BSI,
        detail="enabled" if data.enabled else "disabled",
    )
    return bsi_service.status(db)


@router.post("/fetch")
def fetch_now(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    if not bsi_service.is_enabled(db):
        raise HTTPException(status_code=409, detail="Der BSI-Abruf ist abgeschaltet")
    from ..tasks.data_tasks import fetch_bsi_csaf_task

    try:
        fetch_bsi_csaf_task.delay()
    except Exception:  # noqa: BLE001 - broker (Redis) not reachable
        raise HTTPException(status_code=503, detail="Aufgabe konnte nicht gestartet werden")
    return {"status": "queued"}
