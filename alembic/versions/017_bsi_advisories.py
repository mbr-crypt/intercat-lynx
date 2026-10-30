"""BSI CERT-Bund warnings (index data from the CSAF feed).

Revision ID: 017
Revises: 016
Create Date: 2026-10-25

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "017_bsi_advisories"
down_revision = "016_login_ip"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bsi_advisories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("advisory_id", sa.String(60), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("csaf_url", sa.String(500), nullable=True),
        sa.Column("feed_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("products", sa.JSON(), nullable=True),
        sa.Column("cve_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_bsi_advisories_id", "bsi_advisories", ["id"])
    op.create_index("ix_bsi_advisories_advisory_id", "bsi_advisories", ["advisory_id"], unique=True)
    op.create_index("ix_bsi_advisories_severity", "bsi_advisories", ["severity"])
    op.create_index("ix_bsi_advisories_published_at", "bsi_advisories", ["published_at"])
    op.create_index("ix_bsi_advisories_updated_at", "bsi_advisories", ["updated_at"])

    op.create_table(
        "bsi_advisory_cves",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "advisory_id",
            sa.Integer(),
            sa.ForeignKey("bsi_advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cve_id", sa.String(20), nullable=False),
    )
    op.create_index("ix_bsi_advisory_cves_advisory_id", "bsi_advisory_cves", ["advisory_id"])
    op.create_index("ix_bsi_advisory_cves_cve_id", "bsi_advisory_cves", ["cve_id"])
    op.create_index(
        "uq_bsi_advisory_cve", "bsi_advisory_cves", ["advisory_id", "cve_id"], unique=True
    )


def downgrade() -> None:
    op.drop_table("bsi_advisory_cves")
    op.drop_table("bsi_advisories")
