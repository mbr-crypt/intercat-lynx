"""
Read-only endpoints for Zabbix (HTTP agent items), authenticated with an API token.

- ``GET /summary``: totals over everything the token's owner follows
- ``GET /products``: one entry per followed product, same counters
- ``GET /discovery``: low-level discovery list (macros ``{#KEY}``, ``{#VENDOR}``,
  ``{#PRODUCT}``, ``{#LABEL}``) so Zabbix creates items per product itself
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.api_token import get_token_user
from ..models import User, WatchedProduct
from ..services import watchlist_service as wl
from ..services import zabbix_service

router = APIRouter()


def _watches(db: Session, user: User):
    return (
        db.query(WatchedProduct)
        .filter(WatchedProduct.user_id == user.id)
        .order_by(WatchedProduct.vendor, WatchedProduct.product)
        .all()
    )


@router.get("/summary")
async def summary(user: User = Depends(get_token_user), db: Session = Depends(get_db)):
    total, _ = zabbix_service.compute(db, _watches(db, user))
    return total


@router.get("/products")
async def products(user: User = Depends(get_token_user), db: Session = Depends(get_db)):
    _, items = zabbix_service.compute(db, _watches(db, user))
    return {"items": items}


@router.get("/discovery")
async def discovery(user: User = Depends(get_token_user), db: Session = Depends(get_db)):
    return {
        "data": [
            {
                "{#KEY}": zabbix_service.watch_key(w),
                "{#VENDOR}": w.vendor,
                "{#PRODUCT}": w.product or "",
                "{#LABEL}": wl.watch_label(w.vendor, w.product),
            }
            for w in _watches(db, user)
        ]
    }
