import hashlib
import hmac
import json

import pytest

from wlanpi_mcp.auth.hmac_client import AUTH_ENDPOINT, generate_signature


def test_generate_signature_produces_correct_canonical_string(tmp_path):
    secret = b"supersecret"
    secret_file = tmp_path / "shared_secret.bin"
    secret_file.write_bytes(secret)

    request_body, signature = generate_signature(str(secret_file), "test-device")

    # Verify the body is valid JSON with the right device_id
    body_data = json.loads(request_body)
    assert body_data == {"device_id": "test-device"}

    # Recompute expected signature
    canonical = f"POST\n{AUTH_ENDPOINT}\n\n{request_body}"
    expected = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
    assert signature == expected


def test_generate_signature_different_device_ids_produce_different_signatures(tmp_path):
    secret = b"supersecret"
    secret_file = tmp_path / "shared_secret.bin"
    secret_file.write_bytes(secret)

    _, sig1 = generate_signature(str(secret_file), "device-a")
    _, sig2 = generate_signature(str(secret_file), "device-b")
    assert sig1 != sig2
