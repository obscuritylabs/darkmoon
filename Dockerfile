FROM python:3.10-slim AS darkmoon-base
WORKDIR /opt/app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

FROM darkmoon-base AS darkmoon-builder
RUN pip install poetry
COPY pyproject.toml poetry.lock ./
RUN poetry export --without-hashes -f requirements.txt -o requirements.txt
RUN pip install -r requirements.txt

FROM darkmoon-base AS runner
COPY --from=darkmoon-builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY darkmoon/ darkmoon/
CMD ["python", "-m", "uvicorn", "darkmoon.app:app", "--host=0.0.0.0", "--port=8000"]
