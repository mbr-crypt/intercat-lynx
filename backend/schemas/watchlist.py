"""Schemas for the product selection (watchlist)."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class WatchCreate(BaseModel):
    vendor: str = Field(..., min_length=1, max_length=255)
    # Empty: follow every product of the vendor
    product: Optional[str] = Field(None, max_length=255)


class WatchOut(BaseModel):
    id: int
    vendor: str
    product: Optional[str] = None
    label: str
    created_at: datetime
    cves_7d: int = 0
    cves_30d: int = 0


class CatalogProduct(BaseModel):
    vendor: str
    product: str
    label: str
    cve_count: int
    watched: bool = False


class CatalogVendor(BaseModel):
    vendor: str
    label: str
    product_count: int
    watched: bool = False


class CatalogResult(BaseModel):
    vendors: List[CatalogVendor]
    products: List[CatalogProduct]
    catalog_size: int


class FeedItem(BaseModel):
    cve_id: str
    title: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    published_at: Optional[datetime] = None
    exploited_in_the_wild: bool = False
    products: List[str]


class FeedPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[FeedItem]


class WindowSummary(BaseModel):
    new: int
    critical: int
    high: int
    exploited: int


class WatchSummary(BaseModel):
    watch_count: int
    last_24h: WindowSummary
    last_7d: WindowSummary
