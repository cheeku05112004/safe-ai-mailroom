import base64
import json
import httpx
from pathlib import Path
from cryptography.hazmat.primitives import serialization

private_key = serialization.load_pem_private_key(
    Path("test_private_key.pem").read_bytes(),
    password=None
)

public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

public_key_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")
dossier = json.loads(Path("sample_dossier.json").read_text())

base = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_key_x
        }
    },
    "corpus": {
        "coreId": "LOCAL-CORE",
        "auditId": "LOCAL-AUDIT",
        "stableCount": 1,
        "freshCount": 0
    },
    "allowedActions": [
        "create_draft",
        "update_internal_record",
        "send_approved_notice",
        "request_confirmation",
        "quarantine_item",
        "no_action"
    ],
    "dossiers": [dossier]
}

results = []

for evaluation_id in ["CACHE-CHECK-A", "CACHE-CHECK-B"]:
    data = {**base, "evaluationId": evaluation_id}
    response = httpx.post(
        "http://127.0.0.1:8000/propose",
        json=data,
        timeout=60
    )
    print("\n", evaluation_id, "HTTP", response.status_code)
    print(response.text)

    if response.status_code != 200:
        print("Cache test stopped: request failed.")
        break

    results.append(response.json())

if len(results) == 2:
    first = results[0]["proposals"][0]
    second = results[1]["proposals"][0]

    print("\nSame action:", first["action"] == second["action"])
    print("Same callId:", first["callId"] == second["callId"])
    print("Same target:", first["target"] == second["target"])
    print("Same payload:", first["payload"] == second["payload"])
    print("Same evidence:", first["evidence"] == second["evidence"])
