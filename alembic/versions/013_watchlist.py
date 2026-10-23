"""Product selection: followed products per user and the product catalog.

Revision ID: 013
Revises: 012
Create Date: 2026-10-23

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "013_watchlist"
down_revision = "012_user_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "watched_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vendor", sa.String(255), nullable=False),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_watched_products_id", "watched_products", ["id"])
    op.create_index("ix_watched_products_user_id", "watched_products", ["user_id"])

    op.create_table(
        "product_catalog",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vendor", sa.String(255), nullable=False),
        sa.Column("product", sa.String(255), nullable=False),
        sa.Column("cve_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_product_catalog_id", "product_catalog", ["id"])
    op.create_index("ix_product_catalog_vendor", "product_catalog", ["vendor"])
    op.create_index("ix_product_catalog_product", "product_catalog", ["product"])
    op.create_index(
        "uq_product_catalog_pair", "product_catalog", ["vendor", "product"], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_product_catalog_pair", table_name="product_catalog")
    op.drop_index("ix_product_catalog_product", table_name="product_catalog")
    op.drop_index("ix_product_catalog_vendor", table_name="product_catalog")
    op.drop_index("ix_product_catalog_id", table_name="product_catalog")
    op.drop_table("product_catalog")
    op.drop_index("ix_watched_products_user_id", table_name="watched_products")
    op.drop_index("ix_watched_products_id", table_name="watched_products")
    op.drop_table("watched_products")
