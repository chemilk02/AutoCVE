FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY autocve ./autocve
RUN pip install .

COPY alembic.ini ./
COPY migrations ./migrations

RUN useradd --create-home --uid 10001 autocve
USER autocve

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn autocve.api.app:create_app --factory --host 0.0.0.0 --port 8000"]
