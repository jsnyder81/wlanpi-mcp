import json
import logging
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from wlanpi_mcp.auth.hmac_client import sign_request
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
        # Serialize JSON body ourselves so we control the exact bytes for HMAC
        body_str = ""
        if "json" in kwargs:
            body_str = json.dumps(kwargs.pop("json"), separators=(",", ":"))
            existing = kwargs.pop("headers", {})
            kwargs["content"] = body_str.encode()
            kwargs["headers"] = {**existing, "Content-Type": "application/json"}
        elif "content" in kwargs:
            content = kwargs["content"]
            body_str = content.decode() if isinstance(content, bytes) else (content or "")

        params = kwargs.get("params") or {}
        query_string = urlencode(params) if params else ""

        signature = sign_request(
            self._settings.WLANPI_CORE_SECRET_PATH,
            method.upper(),
            path,
            query_string,
            body_str,
        )

        headers = {**kwargs.pop("headers", {}), "X-Request-Signature": signature}
        response = await self._http.request(method, path, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json()
