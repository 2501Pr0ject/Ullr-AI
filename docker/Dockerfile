# One image for every role. It contains code only: secrets, policy overrides
# and state are mounted at run time. Canon v1 requires Python 3.12 (Unicode 15.0).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build

RUN pip install --no-cache-dir uv==0.13.6
WORKDIR /app
COPY pyproject.toml uv.lock LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Fixed non-root identity shared by every container, so that the containers
# that share a named volume can all use the files in it. The mount points are
# created empty and owned by that user: a new named volume inherits this.
RUN groupadd --gid 10001 ullr \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin ullr \
    && mkdir -p /data/gateway /data/tools /run/episode /episodes/1 /episodes/2 /episodes/3 \
    && chown -R 10001:10001 /data /run/episode /episodes

WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY policies ./policies
COPY attacks ./attacks

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
ENTRYPOINT ["python", "-m", "ullr_ai.serve"]
