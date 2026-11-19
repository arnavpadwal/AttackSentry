# AttackSentry — Core & API

This directory contains the Python backend (engine + API).

```bash
# Run the API server (http://localhost:8000, /api/docs)
../.venv/bin/python -m sentry

# Run tests
../.venv/bin/python -m pytest tests -q

# Apply migrations
../.venv/bin/python -m alembic upgrade head
```

Configuration is via `SENTRY_*` environment variables (see `sentry/config.py`).
See the [root README](../README.md) and [docs/](../docs/) for full documentation.
