import base64
import json
import httpx

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate a local test key pair.
key_path = Path("test_private_key.pem")
private_key = (
    serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if key_path.exists()
    else Ed25519PrivateKey.generate()
)
public_key = private_key.public_key()

Path("test_private_key.pem").write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
public_key_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")

dossier = json.loads(Path("sample_dossier.json").read_text())

request_data = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": "LOCAL-TEST-001",
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_key_x,
        },
    },
    "corpus": {
        "coreId": "LOCAL-CORE",
        "auditId": "LOCAL-AUDIT",
        "stableCount": 1,
        "freshCount": 0,
    },
    "allowedActions": [
        "create_draft",
        "update_internal_record",
        "send_approved_notice",
        "request_confirmation",
        "quarantine_item",
        "no_action",
    ],
    "dossiers": [dossier],
}

try:
    response = httpx.post(
        "http://127.0.0.1:8000/",
        json=request_data,
        timeout=60,
    )
    print("HTTP Status:", response.status_code)
    print(json.dumps(response.json(), indent=2))
except Exception as exc:
    print("Request failed:", str(exc))
