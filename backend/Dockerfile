# OffensiveX API container. Non-root by construction (docs/Guardrail.md:
# containers run non-root; ADR-016).
FROM python:3.12-slim AS base

RUN groupadd --gid 1000 offensivex \
    && useradd --uid 1000 --gid offensivex --shell /bin/bash --create-home offensivex

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./

RUN pip install --no-cache-dir .

USER offensivex

EXPOSE 8000

CMD ["uvicorn", "offensivex.main:app", "--host", "0.0.0.0", "--port", "8000"]
