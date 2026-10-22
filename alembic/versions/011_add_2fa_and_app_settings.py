"""Add two-factor authentication columns and app_settings table.

Revision ID: 011
Revises: 010
Create Date: 2026-10-22

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "011_add_2fa_and_app_settings"
down_revision = "010_add_techstack_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret_enc", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("recovery_codes", sa.JSON(), nullable=True))

    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_column("users", "recovery_codes")
    op.drop_column("users", "totp_last_counter")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret_enc")
