"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-08-20
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sentry.db.base import Base
    from sentry.db import models  # noqa: F401
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # Hypertable conversion is handled in 0002 after primary keys have been
    # made compatible with TimescaleDB's partitioning requirement.


def downgrade() -> None:
    from sentry.db.base import Base
    Base.metadata.drop_all(bind=op.get_bind())
