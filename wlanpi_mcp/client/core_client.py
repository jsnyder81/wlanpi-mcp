import logging
from typing import Any, Optional

import httpx

from wlanpi_mcp.auth.token_context import get_token
from wlanpi_mcp.config import Settings

log = logging.getLogger(__name__)

_client: Optional["CoreClient"] = None


def get_client() -> "CoreClient":
    if _client is None:
        raise RuntimeError("CoreClient not initialized — call init_client() first")
    return _client


def init_client(settings: Settings) -> "CoreClient":
    global _client
    _client = CoreClient(settings)
    return _client


class CoreClient:
    """
    Async client for the wlanpi-core API.

    Auth is pure passthrough: the wlanpi-core JWT presented by the MCP client
    (captured by BearerTokenMiddleware, or WLANPI_CORE_TOKEN for stdio mode)
    is forwarded as the Bearer token on every request. wlanpi-core validates
    it — this server never mints or verifies tokens itself.

    Every request is tagged 'X-Wlanpi-Client: mcp' so core's nginx routes it to
    the JWT validator even when we call over loopback. Without the tag, on-box
    (localhost) requests are forced onto core's HMAC path, which needs a
    root-owned shared secret this unprivileged service cannot read.
    """

    #: Tag read by core's nginx to route on-box calls to the JWT auth path.
    CLIENT_TAG = "mcp"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.WLANPI_CORE_URL,
            timeout=30.0,
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, **kwargs: Any) -> Any:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        return await self._request("POST", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> Any:
        return await self._request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        return await self._request("DELETE", path, **kwargs)

    def _current_token(self) -> str:
        token = get_token() or self._settings.WLANPI_CORE_TOKEN
        if not token:
            raise RuntimeError(
                "No wlanpi-core token available. Connect with "
                "'Authorization: Bearer <token>' (SSE) or set WLANPI_CORE_TOKEN "
                "(stdio). Tokens are issued by wlanpi-core at /api/v1/auth/token."
            )
        return token

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {
            **kwargs.get("headers", {}),
            "Authorization": f"Bearer {self._current_token()}",
            "X-Wlanpi-Client": self.CLIENT_TAG,
        }
        response = await self._http.request(
            method, path, **{**kwargs, "headers": headers}
        )
        response.raise_for_status()
        return response.json()
