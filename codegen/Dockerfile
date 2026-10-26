# syntax=docker/dockerfile:1

FROM erlang:29

RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake libtool just python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/poetry \
    && /opt/poetry/bin/pip install --no-cache-dir poetry==2.5.1 poetry-plugin-export==1.10.1

ENV PATH="/opt/poetry/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_VIRTUALENVS_PATH=/opt/virtualenvs

WORKDIR /project/codegen
COPY codegen/pyproject.toml codegen/poetry.lock ./
RUN poetry install --no-interaction --no-root

WORKDIR /project
