import base64
import json
import httpx

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from app.security import (
    calculate_proposal_digest,
    build_receipt_message,
)

BASE_URL = "http://127.0.0.1:8000"

# Load the same private key used in test_propose.py
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

with httpx.Client(timeout=60) as client:
    # Fetch the original proposal (this should be an exact replay).
    propose_response = client.post(BASE_URL + "/propose", json=request_data)
    print("Propose status:", propose_response.status_code)
    propose_response.raise_for_status()

    result = propose_response.json()
    proposal = result["proposals"][0]

    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": True,
        "proposalDigest": calculate_proposal_digest(proposal),
        "receiptId": "LOCAL-RECEIPT-001",
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

    # Test 1: deliberately invalid signature.
    bad_data = json.loads(json.dumps(commit_data))
    bad_data["receipts"][0]["receiptSignature"] = "AAAA"

    bad_response = client.post(BASE_URL + "/commit", json=bad_data)
    print("Invalid signature status (expected 422):", bad_response.status_code)

    # Test 2: valid signature.
    good_response = client.post(BASE_URL + "/commit", json=commit_data)
    print("Valid signature status:", good_response.status_code)
    print(json.dumps(good_response.json(), indent=2))

    # Test 3: exact commit replay.
    replay_response = client.post(BASE_URL + "/commit", json=commit_data)
    print("Commit replay status:", replay_response.status_code)
    print(
        "Replay response identical:",
        replay_response.json() == good_response.json(),
    )

    # Test 4: changed receipt must be rejected after commit.
    changed_data = json.loads(json.dumps(commit_data))
    changed_data["receipts"][0]["receiptId"] = "DIFFERENT-RECEIPT-ID"

    changed_receipt = changed_data["receipts"][0]
    changed_message = build_receipt_message(
        request_data["profile"],
        result["evaluationId"],
        result["inputDigest"],
        changed_receipt,
    )
    changed_signature = private_key.sign(changed_message)
    changed_receipt["receiptSignature"] = base64.b64encode(
        changed_signature
    ).decode()

    changed_response = client.post(
        BASE_URL + "/commit",
        json=changed_data,
    )

    print(
        "Changed receipt status (expected 409):",
        changed_response.status_code,
    )
    print("Changed receipt response:", changed_response.json())
