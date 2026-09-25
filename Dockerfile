FROM python:3.11.15-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    PATH=/app/.venv/bin:$PATH
WORKDIR /app
COPY pyproject.toml README.md uv.lock /build/signaldesk-web/
COPY src /build/signaldesk-web/src
RUN python -m pip install uv==0.11.31 \
    && cd /build/signaldesk-web \
    && UV_PROJECT_ENVIRONMENT=/app/.venv uv sync --locked --no-dev --no-editable \
    && rm -rf /build
COPY --from=deploy scripts/wait-for-health.py /opt/signaldesk/wait-for-health.py
RUN chmod 0555 /opt/signaldesk/*.py
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "flask", "--app", "signaldesk_web:create_app", "run", "--host", "0.0.0.0", "--port", "8080", "--no-debugger", "--no-reload"]
