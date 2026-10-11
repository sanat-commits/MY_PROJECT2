"""Route packages for Phase 8 API."""

from src.api.routes.health import router as health_router
from src.api.routes.status import router as status_router
from src.api.routes.alerts import router as alerts_router
from src.api.routes.investigations import router as investigations_router

__all__ = [
    "health_router",
    "status_router",
    "alerts_router",
    "investigations_router",
]
