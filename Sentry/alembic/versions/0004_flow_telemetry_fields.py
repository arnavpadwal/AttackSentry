"""persist packet counters and network segment on flow telemetry

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("flow_logs")}
    if "packets_sent" not in columns:
        op.add_column("flow_logs", sa.Column("packets_sent", sa.Integer(), nullable=False, server_default="0"))
    if "packets_received" not in columns:
        op.add_column("flow_logs", sa.Column("packets_received", sa.Integer(), nullable=False, server_default="0"))
    if "subnet" not in columns:
        op.add_column("flow_logs", sa.Column("subnet", sa.String(), nullable=True))
        op.create_index("ix_flow_logs_subnet", "flow_logs", ["subnet"])


def downgrade() -> None:
    op.drop_index("ix_flow_logs_subnet", table_name="flow_logs")
    op.drop_column("flow_logs", "subnet")
    op.drop_column("flow_logs", "packets_received")
    op.drop_column("flow_logs", "packets_sent")
