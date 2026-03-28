"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.http import build_async_client
from app.core.logging import configure_logging, get_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize shared resources on startup and close them on shutdown."""

    configure_logging()
    settings = get_settings()
    logger = get_logger("qroulette.startup")

    logger.info(
        "Starting %s in %s mode",
        settings.app_name,
        settings.app_env,
    )

    app.state.http_client = build_async_client(settings)
    yield
    await app.state.http_client.aclose()

    logger.info("Stopped %s", settings.app_name)


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""

    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router)

    return app


app = create_application()
