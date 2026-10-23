"""Notifications for followed products: per-user settings and delivery log.

Revision ID: 014
Revises: 013
Create Date: 2026-10-23

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "014_notifications"
down_revision = "013_watchlist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("in_app_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("webhook_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("webhook_url", sa.String(1000), nullable=True),
        sa.Column("webhook_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("min_severity", sa.String(20), nullable=False, server_default="HIGH"),
        sa.Column("always_exploited", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_email_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_email_error", sa.Text(), nullable=True),
        sa.Column("last_webhook_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_webhook_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_notification_settings_id", "notification_settings", ["id"])
    op.create_index(
        "ix_notification_settings_user_id", "notification_settings", ["user_id"], unique=True
    )

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_notification_deliveries_id", "notification_deliveries", ["id"])
    op.create_index("ix_notification_deliveries_user_id", "notification_deliveries", ["user_id"])
    op.create_index(
        "uq_notification_delivery",
        "notification_deliveries",
        ["user_id", "vulnerability_id", "channel"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_notification_delivery", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_user_id", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_id", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index("ix_notification_settings_user_id", table_name="notification_settings")
    op.drop_index("ix_notification_settings_id", table_name="notification_settings")
    op.drop_table("notification_settings")
