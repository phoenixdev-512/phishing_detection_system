# ============================================================
# Stage 1: Build React frontend
# ============================================================
FROM node:20-slim AS frontend-builder

WORKDIR /frontend

# Copy package files first for layer caching
# If package.json hasn't changed, npm ci is skipped on rebuild
COPY frontend/package*.json ./
RUN npm ci --prefer-offline

# Copy full frontend source and build
COPY frontend/ ./
RUN npm run build

# Verify the build produced output — fail fast if dist is empty
RUN test -d dist && test -n "$(ls -A dist)" \
    || (echo "ERROR: Vite build produced no output in /frontend/dist" && exit 1)


# ============================================================
# Stage 2: Python backend + compiled frontend
# ============================================================
FROM python:3.11-slim

WORKDIR /app

# ── System dependencies ─────────────────────────────────────
# gcc:   needed by some Python packages (e.g. networkx C extensions)
# whois: runtime dependency for python-whois subprocess calls
# curl:  used by healthcheck and setup.sh
# ca-certificates: required for HTTPS calls to PDNS, crt.sh, RDAP
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    whois \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──────────────────────────────────────
# Copy requirements first — layer is cached unless requirements.txt changes
COPY requirements.txt .
RUN cat requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application source ───────────────────────────────────────
COPY app/ ./app/
COPY seed_db.py .

# ── Compiled frontend from Stage 1 ──────────────────────────
# FastAPI serves this directory as static files at GET /
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# ── Runtime directories ──────────────────────────────────────
# /data  → SQLite database file (mount a volume here in production)
# /data/corpus → brand/keyword corpus JSON files
# /data/ml    → trained ML model pickle
RUN mkdir -p /data/corpus /data/ml

# ── Non-root user for security ───────────────────────────────
# Running as root inside a container is a security risk.
# Create a dedicated user and transfer ownership.
RUN groupadd --gid 1001 tgis \
    && useradd --uid 1001 --gid tgis --shell /bin/bash --create-home tgis \
    && chown -R tgis:tgis /app /data

USER tgis

# ── Environment defaults ─────────────────────────────────────
# These are safe defaults for local/Docker use.
# Override all of these via docker-compose environment: or -e flags.
# IMPORTANT: ALLOWED_ORIGINS must be a valid JSON array string.
ENV DATABASE_URL="/data/phishing_db.sqlite"
ENV ALLOWED_ORIGINS='["http://localhost:8000","http://localhost:3000","http://localhost:5173"]'
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE="1"
ENV PYTHONUNBUFFERED="1"
ENV TGIS_TIMEOUT_MS="200"
ENV RATE_LIMIT_PER_MINUTE="30"
ENV SCP_AGE_THRESHOLD_DAYS="1.0"
ENV TGIS_ALPHA="0.55"
ENV TGIS_BETA="0.30"
ENV TGIS_GAMMA="0.15"

# ── Expose port ──────────────────────────────────────────────
EXPOSE 8000

# ── Healthcheck ──────────────────────────────────────────────
# Docker will mark the container unhealthy if /health stops responding.
# start_period gives the app time to seed the DB and start up.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# ── Entrypoint ───────────────────────────────────────────────
# Using a proper entrypoint script instead of CMD chaining with &&
# so that if seed_db.py fails, we get a clear error rather than
# a silent container exit.
COPY --chown=tgis:tgis docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
