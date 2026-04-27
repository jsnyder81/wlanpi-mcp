import logging
from typing import Any, Optional

import httpx

from wlanpi_mcp.auth.token_manager import TokenManager
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
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._token_manager = TokenManager(settings)
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

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        token = await self._token_manager.get_token()
        headers = {**kwargs.pop("headers", {}), "Authorization": f"Bearer {token}"}

        response = await self._http.request(method, path, headers=headers, **kwargs)

        if response.status_code == 401:
            # Token may be stale — force one refresh and retry
            self._token_manager.invalidate()
            token = await self._token_manager.get_token()
            headers["Authorization"] = f"Bearer {token}"
            response = await self._http.request(
                method, path, headers=headers, **kwargs
            )

        response.raise_for_status()
        return response.json()
