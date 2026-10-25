"""
Public branding endpoints: the pages (also the login page) draw name, colour,
footer text and logo from here. No login needed, nothing secret in it.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..services import branding_service

router = APIRouter()


@router.get("")
async def get_branding(response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-cache"
    return branding_service.get_branding(db)


@router.get("/logo/{variant}")
async def get_logo(variant: str, db: Session = Depends(get_db)):
    found = branding_service.read_logo(db, variant)
    if found is None:
        raise HTTPException(status_code=404, detail="Kein Logo hinterlegt")
    data, mime = found
    return Response(
        content=data,
        media_type=mime,
        headers={
            # The address carries ?v=<version>, so a changed logo gets a new address
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
            # Even if someone opened the file directly: nothing may run from it
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )
