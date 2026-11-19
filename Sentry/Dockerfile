# AttackSentry backend (core + API)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for compiled wheels (psycopg, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# The autoencoders are tiny; CPU-only torch keeps the image small and avoids
# pulling ~7 GB of CUDA runtime that is never used at inference time.
RUN pip install --upgrade pip \
    && pip install --index-url https://download.pytorch.org/whl/cpu torch==2.10.0 \
    && pip install -r requirements.txt

COPY . .

RUN groupadd --system attacksentry \
    && useradd --system --gid attacksentry --home-dir /app attacksentry \
    && mkdir -p /app/models /app/data \
    && chown -R attacksentry:attacksentry /app

USER attacksentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fs http://localhost:8000/healthz || exit 1

CMD ["sh", "-c", "alembic upgrade head && exec python -m sentry"]
