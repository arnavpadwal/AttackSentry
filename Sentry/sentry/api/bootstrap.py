"""Startup bootstrap: seed admin user and default suppression rules."""
from __future__ import annotations

import logging

from sqlalchemy import func, select

from ..config import settings
from ..db import session_factory
from ..db.models import SuppressionRule, SystemConfig, User
from .security import hash_password

logger = logging.getLogger("sentry.bootstrap")

_DEFAULT_SUPPRESSIONS = [
    {"name": "Multicast discovery noise", "subnet": "224.0.0.0/4", "reason": "Expected multicast discovery traffic"},
]

_SETUP_DONE = {"is_setup_complete": True, "current_step": 7,
               "steps_completed": ["welcome", "auth", "environment", "sensors", "integrations", "baseline", "review"]}


async def bootstrap() -> None:
    async with session_factory() as db:
        user_count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
        if user_count == 0:
            admin_pass = settings.bootstrap_admin_password or _generate_initial_password()
            db.add(User(
                email=settings.bootstrap_admin_email,
                username=settings.bootstrap_admin_username,
                hashed_password=hash_password(admin_pass),
                full_name="Administrator",
                role="admin",
            ))
            if settings.is_production:
                logger.warning(
                    "Created bootstrap admin '%s'; change the configured bootstrap password immediately",
                    settings.bootstrap_admin_username,
                )
            else:
                logger.warning(
                    "Created development bootstrap admin '%s' (password=%s)",
                    settings.bootstrap_admin_username, admin_pass,
                )
        rule_count = (await db.execute(select(func.count()).select_from(SuppressionRule))).scalar() or 0
        if rule_count == 0:
            for r in _DEFAULT_SUPPRESSIONS:
                db.add(SuppressionRule(**r))

        # Mark onboarding complete by default — the bootstrap admin is the
        # setup step; there is no mandatory multi-step wizard.
        cfg = (await db.execute(select(SystemConfig).where(SystemConfig.key == "setup"))).scalar_one_or_none()
        if not cfg:
            db.add(SystemConfig(key="setup", value=_SETUP_DONE))

        # Older development builds could leave an empty placeholder user.
        blank_users = (await db.execute(
            select(User).where(User.username == "", User.email == "")
        )).scalars().all()
        for blank in blank_users:
            await db.delete(blank)

        runtime = (await db.execute(select(SystemConfig).where(SystemConfig.key == "runtime_settings"))).scalar_one_or_none()
        if runtime:
            for key, value in (runtime.value or {}).items():
                if hasattr(settings, key):
                    setattr(settings, key, value)

        await db.commit()


def _generate_initial_password() -> str:
    import secrets
    return secrets.token_urlsafe(12)
