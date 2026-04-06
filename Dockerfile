# Stage 1: Build React frontend
FROM node:20-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Python backend + compiled frontend
FROM python:3.11-slim
WORKDIR /app

# System dependencies for python-whois and networkx
RUN apt-get update && apt-get install -y \
    gcc \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY app/ ./app/
COPY seed_db.py .

# Copy compiled frontend from builder stage
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# Create data directory for SQLite
RUN mkdir -p /data

# Environment defaults
ENV DATABASE_URL=/data/phishing_db.sqlite
ENV ALLOWED_ORIGINS=["http://localhost:8000","http://localhost:3000"]
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Seed the database and start the server
CMD python seed_db.py && \
    uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info
