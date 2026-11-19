"""add auditable mitigation actions

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("mitigation_actions"):
        return
    op.create_table(
        "mitigation_actions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("entity", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("requested_by", sa.String(), nullable=True),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_message", sa.Text(), nullable=True),
    )
    op.create_index("ix_mitigation_actions_incident_id", "mitigation_actions", ["incident_id"])
    op.create_index("ix_mitigation_actions_entity", "mitigation_actions", ["entity"])
    op.create_index("ix_mitigation_actions_status", "mitigation_actions", ["status"])
    op.create_index("ix_mitigation_actions_created_at", "mitigation_actions", ["created_at"])


def downgrade() -> None:
    op.drop_table("mitigation_actions")
