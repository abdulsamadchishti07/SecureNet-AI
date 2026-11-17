# syntax=docker/dockerfile:1
FROM node:22-alpine AS dashboard
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS server
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8010
WORKDIR /app
COPY requirements-docker.txt ./
RUN python -m pip install --no-cache-dir --timeout 60 --retries 8 -r requirements-docker.txt \
    && python -m pip check \
    && groupadd --gid 1000 securenet \
    && useradd --uid 1000 --gid securenet --no-create-home securenet \
    && mkdir -p /app/runtime \
    && chown securenet:securenet /app/runtime
COPY backend/ ./backend/
COPY ml_engine/__init__.py ml_engine/datasets.py ml_engine/preprocess.py ./ml_engine/
COPY sniffer/__init__.py sniffer/events.py ./sniffer/
COPY --from=dashboard /build/frontend/dist/ ./frontend/dist/
USER securenet
EXPOSE 8010
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('UVICORN_PORT', '8010') + '/api/health', timeout=3).close()"]
CMD ["python", "-m", "uvicorn", "backend.main:app", "--workers", "1", "--no-access-log", "--log-level", "warning"]
