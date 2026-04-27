from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from wlanpi_mcp.config import Settings


class APIKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self._api_key = settings.WLANPI_MCP_API_KEY

    async def dispatch(self, request: Request, call_next):
        if not self._api_key:
            return await call_next(request)

        key = request.headers.get("X-API-Key") or request.headers.get(
            "Authorization", ""
        ).removeprefix("Bearer ").strip()

        if key != self._api_key:
            return JSONResponse(
                {"detail": "Invalid or missing API key"}, status_code=401
            )

        return await call_next(request)
