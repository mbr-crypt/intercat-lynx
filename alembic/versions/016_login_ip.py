"""Remember the address of the last login (lockout is not a weapon against it).

Revision ID: 016
Revises: 015
Create Date: 2026-10-23

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "016_login_ip"
down_revision = "015_api_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_login_ip", sa.String(45), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "last_login_ip")
