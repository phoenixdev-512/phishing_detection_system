import logging
import os
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

app = FastAPI(title=getattr(settings, "PROJECT_NAME", "Phishing URL Analyzer"))

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    env_api_key = os.getenv("API_KEY")
    if env_api_key and request.url.path.startswith(getattr(settings, "API_V1_STR", "/api/v1")):        
        api_key = request.headers.get("X-API-Key")
        if api_key != env_api_key:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Invalid or missing API Key"}
            )
    return await call_next(request)

# Include the new scan router
try:
    from app.api.v1.endpoints import scan
    app.include_router(scan.router, prefix=getattr(settings, "API_V1_STR", "/api/v1"))
except ImportError:
    pass

# TODO: Include app.api.v1.endpoints.history when available
# TODO: Include app.api.v1.endpoints.stats when available
try:
    from app.api.endpoints import router as api_router
    app.include_router(api_router, prefix=getattr(settings, "API_V1_STR", "/api/v1"))
except ImportError:
    pass

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal pipeline error", "detail": str(exc)}
    )

try:
    app.mount("/", StaticFiles(directory="frontend/dist", html=True), name="static")
except RuntimeError:
    @app.get("/")
    def read_root():
        return {"message": "Phishing URL Analyzer Backend is Running. React Frontend not compiled yet."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
