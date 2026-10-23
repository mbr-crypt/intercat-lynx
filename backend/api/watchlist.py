"""
Product selection: every user follows the products that matter to them and
sees which CVEs concern those products.

Any signed-in user (viewer and up) can use this; everything is scoped to the
caller's own list. Rebuilding the product catalog is an admin action.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import get_current_user, require_admin
from ..models import ProductCatalog, User, Vulnerability, WatchedProduct
from ..schemas.watchlist import (
    CatalogProduct,
    CatalogResult,
    CatalogVendor,
    FeedItem,
    FeedPage,
    WatchCreate,
    WatchOut,
    WatchSummary,
    WindowSummary,
)
from ..services import watchlist_service as wl

logger = logging.getLogger(__name__)

router = APIRouter()


def _my_watches(db: Session, user: User):
    return (
        db.query(WatchedProduct)
        .filter(WatchedProduct.user_id == user.id)
        .order_by(WatchedProduct.vendor, WatchedProduct.product)
        .all()
    )


def _watch_out(db: Session, w: WatchedProduct) -> WatchOut:
    return WatchOut(
        id=w.id,
        vendor=w.vendor,
        product=w.product,
        label=wl.watch_label(w.vendor, w.product),
        created_at=w.created_at,
        cves_7d=wl.matching_query(db, [w], since=wl.utc_since(7)).count(),
        cves_30d=wl.matching_query(db, [w], since=wl.utc_since(30)).count(),
    )


@router.get("", response_model=list[WatchOut])
async def list_watches(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """The products I follow, with how many CVEs concern each of them lately."""
    return [_watch_out(db, w) for w in _my_watches(db, user)]


@router.post("", response_model=WatchOut, status_code=status.HTTP_201_CREATED)
async def add_watch(
    data: WatchCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Follow a product (or all products of a vendor). Must exist in the catalog."""
    vendor = wl.slug(data.vendor)
    product = wl.slug(data.product) if data.product and data.product.strip() else None
    if not vendor:
        raise HTTPException(status_code=422, detail="Vendor is required")

    known = db.query(ProductCatalog).filter(ProductCatalog.vendor == vendor)
    if product:
        known = known.filter(ProductCatalog.product == product)
    if known.first() is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown product. Pick one from the search results.",
        )

    existing = _my_watches(db, user)
    if len(existing) >= wl.MAX_WATCHES_PER_USER:
        raise HTTPException(
            status_code=400,
            detail=f"At most {wl.MAX_WATCHES_PER_USER} followed products per user",
        )
    if any(w.vendor == vendor and w.product == product for w in existing):
        raise HTTPException(status_code=409, detail="Already following this product")

    watch = WatchedProduct(user_id=user.id, vendor=vendor, product=product)
    db.add(watch)
    db.commit()
    db.refresh(watch)
    return _watch_out(db, watch)


@router.delete("/{watch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_watch(
    watch_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    watch = (
        db.query(WatchedProduct)
        .filter(WatchedProduct.id == watch_id, WatchedProduct.user_id == user.id)
        .first()
    )
    if watch is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(watch)
    db.commit()


@router.get("/catalog", response_model=CatalogResult)
async def search_catalog(
    q: str = Query("", max_length=100),
    limit: int = Query(15, ge=1, le=50),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search vendors and products that occur in the CVE data."""
    term = wl.slug(q)
    size = db.query(func.count(ProductCatalog.id)).scalar() or 0
    if not term:
        return CatalogResult(vendors=[], products=[], catalog_size=size)

    like = f"%{wl._escape(term)}%"
    mine = _my_watches(db, user)
    watched_vendors = {w.vendor for w in mine if not w.product}
    watched_pairs = {(w.vendor, w.product) for w in mine if w.product}

    vendor_rows = (
        db.query(
            ProductCatalog.vendor,
            func.count(ProductCatalog.id).label("n"),
        )
        .filter(ProductCatalog.vendor.like(like, escape="\\"))
        .group_by(ProductCatalog.vendor)
        .order_by(func.sum(ProductCatalog.cve_count).desc())
        .limit(limit)
        .all()
    )
    product_rows = (
        db.query(ProductCatalog)
        .filter(
            or_(
                ProductCatalog.product.like(like, escape="\\"),
                ProductCatalog.vendor.like(like, escape="\\"),
            )
        )
        .order_by(ProductCatalog.cve_count.desc())
        .limit(limit)
        .all()
    )
    return CatalogResult(
        catalog_size=size,
        vendors=[
            CatalogVendor(
                vendor=v,
                label=wl.label(v),
                product_count=n,
                watched=v in watched_vendors,
            )
            for v, n in vendor_rows
        ],
        products=[
            CatalogProduct(
                vendor=r.vendor,
                product=r.product,
                label=wl.watch_label(r.vendor, r.product),
                cve_count=r.cve_count,
                watched=(r.vendor, r.product) in watched_pairs
                or r.vendor in watched_vendors,
            )
            for r in product_rows
        ],
    )


@router.post("/catalog/rebuild")
async def rebuild_catalog(
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Recount the product catalog from the CVE data (admin)."""
    return wl.rebuild_catalog(db)


@router.get("/feed", response_model=FeedPage)
async def feed(
    days: int = Query(30, ge=1, le=365),
    min_severity: Optional[str] = Query(None, description="low, medium, high or critical"),
    exploited_only: bool = False,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """CVEs that concern the products I follow, newest first."""
    if min_severity and wl.severities_from(min_severity) is None:
        raise HTTPException(
            status_code=422, detail="min_severity must be low, medium, high or critical"
        )
    watches = _my_watches(db, user)
    query = wl.matching_query(
        db,
        watches,
        since=wl.utc_since(days),
        min_severity=min_severity,
        kev_only=exploited_only,
    )
    total = query.count()
    rows = (
        query.order_by(Vulnerability.published_at.desc(), Vulnerability.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = [
        FeedItem(
            cve_id=v.cve_id,
            title=v.simple_title or v.title,
            severity=v.severity,
            cvss_score=v.cvss_score,
            published_at=v.published_at,
            exploited_in_the_wild=bool(v.exploited_in_the_wild),
            products=[wl.watch_label(w.vendor, w.product) for w in wl.matching_watches(v, watches)],
        )
        for v in rows
    ]
    return FeedPage(total=total, page=page, page_size=page_size, items=items)


@router.get("/summary", response_model=WatchSummary)
async def summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Counts for a dashboard tile: what is new for my products."""
    watches = _my_watches(db, user)
    return WatchSummary(
        watch_count=len(watches),
        last_24h=WindowSummary(**wl.window_counts(db, watches, 1)),
        last_7d=WindowSummary(**wl.window_counts(db, watches, 7)),
    )
