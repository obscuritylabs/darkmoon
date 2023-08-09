FROM python:3.10-slim AS darkmoon-base
WORKDIR /opt/app
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100
# TODO from Tory: Make this install cleaner
RUN apt update -y && apt install -y libmagic1

FROM darkmoon-base AS darkmoon-builder
RUN pip install poetry
COPY pyproject.toml poetry.lock ./
RUN poetry export --without-hashes -f requirements.txt -o requirements.txt
RUN pip install -r requirements.txt

FROM darkmoon-base AS runner
COPY --from=darkmoon-builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY darkmoon/ darkmoon/
RUN apt-get update && apt-get install p7zip-full -y --no-install-recommends
CMD ["python", "-m", "uvicorn", "--factory", "darkmoon.app:get_app", "--host=0.0.0.0", "--port=8000"]
