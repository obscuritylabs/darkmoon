# Copyright (C) 2022 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

FROM python:3.10-slim AS darkmoon-base
WORKDIR /opt/app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

FROM darkmoon-base AS darkmoon-builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev g++ libxml2-dev libxslt-dev python3-dev && \
    rm -rf /var/lib/apt/lists/*
RUN pip install poetry
COPY pyproject.toml poetry.lock ./
RUN poetry export --without-hashes -f requirements.txt -o requirements.txt
RUN pip install -r requirements.txt
COPY src .
RUN poetry build && pip install dist/*.whl

FROM darkmoon-base AS runner
COPY --from=darkmoon-builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
ENV PRODUCTION=true \
    STATIC_PATH=/opt/app/
CMD ["python", "-m", "uvicorn", "darkmoon.main:app", "--host=0.0.0.0", "--port=8000"]
