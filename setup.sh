#!/bin/bash
# Run with: bash setup.sh
# Or first: chmod +x setup.sh && ./setup.sh
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step()  { echo -e "\n${BOLD}${BLUE}──── $1 ────${NC}"; }

echo -e "${BOLD}${BLUE}TGIS PHISHING DETECTION SYSTEM${NC}"
echo -e "Automated Setup & Deployment Script\n"

step "Checking prerequisites"

if ! command -v docker >/dev/null 2>&1; then
    error "Docker is not installed."
fi

if ! docker info >/dev/null 2>&1; then
    error "Docker is not running. Please start the Docker daemon."
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    error "Docker compose is not installed."
fi
log "Using Docker Compose command: $COMPOSE_CMD"

step "Checking project structure"

for f in "app/main.py" "frontend/package.json" "requirements.txt"; do
    if [ ! -f "$f" ]; then
        warn "Missing file: $f"
    fi
done

if [ ! -d "frontend/dist" ]; then
    warn "frontend/dist/ does not exist. Frontend will be built inside Docker."
fi

step "Creating environment configuration"

if [ ! -f ".env" ]; then
    cat <<EOF > .env
DATABASE_URL=/data/phishing_db.sqlite
ALLOWED_ORIGINS=["http://localhost:8000","http://localhost:3000"]
TGIS_TIMEOUT_MS=200
RATE_LIMIT_PER_MINUTE=30
SCP_AGE_THRESHOLD_DAYS=1.0
TGIS_ALPHA=0.55
TGIS_BETA=0.30
TGIS_GAMMA=0.15
EOF
    log "Created .env with default configuration"
else
    log "Using existing .env configuration"
fi

step "Building and starting services"

if ! $COMPOSE_CMD build --no-cache; then
    error "Docker build failed. Check the output above."
fi

if ! $COMPOSE_CMD up -d; then
    error "Failed to start containers."
fi
log "Containers started"

step "Waiting for backend to be healthy"

MAX_WAIT=60
WAIT=0
while [ $WAIT -lt $MAX_WAIT ]; do
    if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        log "Backend is healthy"
        break
    fi
    echo -n "."
    sleep 2
    WAIT=$((WAIT + 2))
done
if [ $WAIT -ge $MAX_WAIT ]; then
    error "Backend did not start within ${MAX_WAIT}s. Run: $COMPOSE_CMD logs"
fi

step "Seeding initial database"

if $COMPOSE_CMD exec -T tgis-backend python seed_db.py; then
    log "Database seeded"
else
    warn "Seed script had issues (database may already be seeded)"
fi

step "Verifying scan endpoint"

TEST_RESPONSE=$(curl -sf -X POST http://localhost:8000/api/v1/scan \
    -H "Content-Type: application/json" \
    -d '{"url":"http://example.com"}' 2>/dev/null || true)

if echo "$TEST_RESPONSE" | grep -q '"status"'; then
    log "Scan endpoint verified and returning results"
else
    warn "Scan endpoint returned unexpected response"
    warn "Run: curl -X POST http://localhost:8000/api/v1/scan -H 'Content-Type: application/json' -d '{\"url\":\"http://example.com\"}'"
fi

echo -e "\n${BOLD}${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   TGIS SYSTEM IS RUNNING SUCCESSFULLY     ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "  ${BOLD}Dashboard:${NC}      http://localhost:8000"
echo -e "  ${BOLD}API Docs:${NC}       http://localhost:8000/docs"
echo -e "  ${BOLD}Health:${NC}         http://localhost:8000/api/v1/health"
echo -e "  ${BOLD}Scan Endpoint:${NC}  POST http://localhost:8000/api/v1/scan"
echo -e ""
echo -e "  ${BOLD}Extension:${NC} Load extension/ folder in Chrome:"
echo -e "    chrome://extensions → Developer Mode → Load unpacked"
echo -e ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "    View logs:    ${BLUE}$COMPOSE_CMD logs -f${NC}"
echo -e "    Stop:         ${BLUE}$COMPOSE_CMD down${NC}"
echo -e "    Restart:      ${BLUE}$COMPOSE_CMD restart${NC}"
echo -e "    Shell:        ${BLUE}$COMPOSE_CMD exec tgis-backend bash${NC}"
