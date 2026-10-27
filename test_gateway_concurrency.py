import base64
import json
import httpx

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import serialization

from app.security import (
    calculate_proposal_digest,
    build_receipt_message,
)

BASE_URL = "https://safe-ai-mailroom-tmkd.onrender.com"

private_key = serialization.load_pem_private_key(
    Path("test_private_key.pem").read_bytes(),
    password=None,
)

public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
public_key_x = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")

dossier = json.loads(Path("sample_dossier.json").read_text())

request_data = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": "GW-CONCURRENCY-20261027-01",
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

response = httpx.post(BASE_URL + "/", json=request_data, timeout=60)
print("Propose status:", response.status_code)
response.raise_for_status()

result = response.json()
proposal = result["proposals"][0]

receipt = {
    "dossierId": proposal["dossierId"],
    "callId": proposal["callId"],
    "action": proposal["action"],
    "accepted": True,
    "proposalDigest": calculate_proposal_digest(proposal),
    "receiptId": "CONCURRENCY-RECEIPT-001",
}

message = build_receipt_message(
    request_data["profile"],
    result["evaluationId"],
    result["inputDigest"],
    receipt,
)

signature = private_key.sign(message)
receipt["receiptSignature"] = base64.b64encode(signature).decode()

commit_data = {
    "profile": request_data["profile"],
    "operation": "commit",
    "evaluationId": result["evaluationId"],
    "inputDigest": result["inputDigest"],
    "receipts": [receipt],
}

def send_commit():
    return httpx.post(
        BASE_URL + "/",
        json=commit_data,
        timeout=60,
    )

print("\nSending two simultaneous commit requests...")

with ThreadPoolExecutor(max_workers=2) as executor:
    futures = [
        executor.submit(send_commit),
        executor.submit(send_commit),
    ]
    responses = [future.result() for future in futures]

for index, response in enumerate(responses, 1):
    print(f"Request {index} status:", response.status_code)

    if response.status_code != 200:
        print(response.text)

assert all(r.status_code == 200 for r in responses), \
    "At least one concurrent commit failed."

assert responses[0].json() == responses[1].json(), \
    "Concurrent commit responses are not identical."

print("\nPASS: Both concurrent commits returned HTTP 200.")
print("PASS: Both responses are identical.")
print("Evaluation ID:", result["evaluationId"])
