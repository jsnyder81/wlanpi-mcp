import hashlib
import hmac
import json
from pathlib import Path
from urllib.parse import urlencode


AUTH_ENDPOINT = "/api/v1/auth/token"


def sign_request(
    secret_path: str,
    method: str,
    path: str,
    query_string: str = "",
    body: str = "",
) -> str:
    """
    Generate HMAC-SHA256 signature for a wlanpi-core localhost API request.
    Canonical string mirrors wlanpi_core/core/auth.py verify_hmac exactly:
      METHOD\nPATH\nQUERY_STRING\nBODY
    """
    canonical = f"{method}\n{path}\n{query_string}\n{body}"
    secret = Path(secret_path).read_bytes()
    return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()


def generate_signature(secret_path: str, device_id: str) -> tuple[str, str]:
    """Legacy helper kept for reference — not used by CoreClient."""
    request_body = json.dumps({"device_id": device_id})
    sig = sign_request(secret_path, "POST", AUTH_ENDPOINT, "", request_body)
    return request_body, sig
