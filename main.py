"""
WalletGuard – FastAPI Backend
AI-powered wallet security scanner with OpenGradient TEE.
"""

import logging
import os
from contextlib import asynccontextmanager

# Load .env FIRST
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from routes.scan_wallet import router as scan_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("walletguard")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WalletGuard backend starting up...")
    yield
    logger.info("WalletGuard backend shutting down...")


# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title="WalletGuard API",
    description=(
        "AI-powered wallet security scanner. "
        "Verifiable risk analysis via OpenGradient LLM + TEE."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware & CORS
# ---------------------------------------------------------------------------
# Pull allowed origins from .env for Vercel/Production safety
# Example: ALLOWED_ORIGINS=https://your-app.vercel.app,http://localhost:3000
raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
origins = [origin.strip() for origin in raw_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers & Endpoints
# ---------------------------------------------------------------------------
app.include_router(scan_router, prefix="/api/v1", tags=["Wallet Scanner"])

@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to Swagger UI for easy testing on Vercel."""
    return RedirectResponse(url="/docs")

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "WalletGuard", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Global Exception Handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )