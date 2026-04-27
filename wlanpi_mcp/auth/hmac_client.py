import hashlib
import hmac
import json
from pathlib import Path


AUTH_ENDPOINT = "/api/v1/auth/token"


def generate_signature(secret_path: str, device_id: str) -> tuple[str, str]:
    """
    Returns (request_body_json, hmac_signature) for the auth token endpoint.
    Canonical string format mirrors wlanpi_core/cli/getjwt.py exactly.
    """
    request_body = json.dumps({"device_id": device_id})
    canonical_string = f"POST\n{AUTH_ENDPOINT}\n\n{request_body}"

    secret = Path(secret_path).read_bytes()
    signature = hmac.new(
        secret, canonical_string.encode(), hashlib.sha256
    ).hexdigest()

    return request_body, signature
