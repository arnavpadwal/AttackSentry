"""Entry point: ``python -m sentry`` runs the AttackSentry API server."""
from __future__ import annotations

import uvicorn

from .config import settings


def main() -> None:
    uvicorn.run(
        "sentry.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
