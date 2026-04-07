#!/bin/bash
# docker-entrypoint.sh
# Runs inside the container on every start.
# Using bash -e so any failure exits immediately with a visible error.
set -e

echo "──────────────────────────────────────────"
echo "  TGIS Phishing Detection System"
echo "  Container starting up..."
echo "──────────────────────────────────────────"

# ── Seed / migrate the database ──────────────────────────────
# seed_db.py must be idempotent (safe to run on every container start).
# It creates tables if missing and inserts test data if the DB is empty.
echo "[1/3] Initializing database at ${DATABASE_URL}..."
python seed_db.py \
    && echo "      Database ready." \
    || { echo "ERROR: seed_db.py failed. Check the output above."; exit 1; }

# ── Copy default corpus if none exists ───────────────────────
# If the /data/corpus volume is empty on first run, seed the default corpus.
if [ ! -f "/data/corpus/brands_v1.json" ] && [ -f "/app/data/corpus/brands_v1.json" ]; then
    cp /app/data/corpus/brands_v1.json /data/corpus/brands_v1.json
    echo "      Default brand corpus seeded."
fi

# ── Start the FastAPI server ─────────────────────────────────
echo "[2/3] Starting FastAPI server..."
echo "      Listening on http://0.0.0.0:8000"
echo "      Dashboard:  http://localhost:8000/"
echo "      API docs:   http://localhost:8000/docs"
echo "      Health:     http://localhost:8000/api/v1/health"
echo "──────────────────────────────────────────"

echo "[3/3] Handing off to uvicorn..."

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --loop asyncio \
    --log-level info \
    --access-log
