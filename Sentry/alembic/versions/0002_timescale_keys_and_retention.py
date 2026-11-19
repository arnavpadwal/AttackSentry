"""make time-series keys Timescale-compatible and enable retention

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from sentry.config import settings

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ("flow_logs", "detections", "audit_log")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    inspector = sa.inspect(bind)
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    for table in TABLES:
        primary_key = inspector.get_pk_constraint(table)
        columns = primary_key.get("constrained_columns") or []
        if "timestamp" not in columns:
            constraint = primary_key.get("name") or f"{table}_pkey"
            op.drop_constraint(constraint, table, type_="primary")
            op.create_primary_key(f"{table}_pkey", table, ["id", "timestamp"])
        op.execute(f"SELECT create_hypertable('{table}', 'timestamp', if_not_exists => TRUE)")
        op.execute(
            f"SELECT add_retention_policy('{table}', INTERVAL '{int(settings.retention_days)} days', if_not_exists => TRUE)"
        )


def downgrade() -> None:
    # Hypertable conversion and evidence deletion policies are deliberately not
    # reversed automatically. Restore from a tested backup for a full downgrade.
    pass
